// Package baseline records what a target looked like on a previous scan so
// changes can be detected.
//
// This is the answer to a rug pull: a server serves clean tool descriptions
// while it is being reviewed, then swaps in malicious ones once it has been
// approved. Every check detonate performs otherwise is a snapshot, and a
// snapshot cannot see a swap by definition — you need two.
//
// The store is deliberately plain: JSON files under the user's config
// directory, one per target, readable and deletable by hand. A scanner whose
// state a user cannot inspect is a scanner they cannot trust, and the volume
// here (a few hundred bytes per target) never justifies a database.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/m4vic/detonate/internal/toolinfo"
	"github.com/m4vic/detonate/internal/trace"
)

// Record is what a target looked like at one point in time.
type Record struct {
	Target       string            `json:"target"`
	RecordedAt   time.Time         `json:"recorded_at"`
	Tools        map[string]string `json:"tools"`        // tool name -> description hash
	Descriptions map[string]string `json:"descriptions"` // name -> description, for the diff
}

// Dir returns where baselines live, creating it if needed.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "detonate", "baselines")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating baseline directory: %w", err)
	}
	return dir, nil
}

// keyFor turns a target reference into a stable filename.
//
// Hashed rather than sanitised because a target is a command line or a path,
// and both contain characters that are illegal in filenames on some platform
// or another. A hash sidesteps the whole class of problem.
func keyFor(target string) string {
	sum := sha256.Sum256([]byte(target))
	return hex.EncodeToString(sum[:8]) + ".json"
}

// Capture builds a record from a scan's discovered tools.
func Capture(target string, tools []toolinfo.ToolInfo) Record {
	r := Record{
		Target:       target,
		RecordedAt:   time.Now(),
		Tools:        map[string]string{},
		Descriptions: map[string]string{},
	}
	for _, t := range tools {
		sum := sha256.Sum256([]byte(t.Description))
		r.Tools[t.Name] = hex.EncodeToString(sum[:])
		r.Descriptions[t.Name] = t.Description
	}
	return r
}

// Load returns the stored record for a target, and whether one existed.
func Load(target string) (Record, bool, error) {
	dir, err := Dir()
	if err != nil {
		return Record{}, false, err
	}
	data, err := os.ReadFile(filepath.Join(dir, keyFor(target)))
	if os.IsNotExist(err) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}

	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		// A corrupt baseline is not worth failing a scan over. Treat it as
		// absent: the scan still runs and simply records a fresh one.
		return Record{}, false, nil
	}
	return r, true, nil
}

// Save writes a record, replacing any previous one.
func Save(r Record) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, keyFor(r.Target)), data, 0o644)
}

// Compare reports what changed between a stored baseline and a fresh scan.
//
// A changed description is the headline case and the reason this package
// exists. It is not automatically malicious — servers update — but it means
// the thing a user approved is not the thing they are now running, and that is
// exactly the decision point a rug pull relies on nobody noticing.
func Compare(old, current Record) []trace.Event {
	var events []trace.Event
	now := time.Now()

	for name, hash := range current.Tools {
		prev, existed := old.Tools[name]
		switch {
		case !existed:
			events = append(events, trace.Event{
				Kind: trace.KindProtocol, Severity: trace.SeverityNotable, At: now,
				Summary: fmt.Sprintf("new tool %q appeared since the last scan", name),
				During:  "baseline-diff", Source: "baseline",
				Detail: map[string]any{
					"evidence": clip(current.Descriptions[name], 200),
					"since":    old.RecordedAt.Format(time.RFC3339),
				},
			})
		case prev != hash:
			// The rug pull.
			events = append(events, trace.Event{
				Kind: trace.KindProtocol, Severity: trace.SeverityCritical, At: now,
				Summary: fmt.Sprintf("tool %q changed its description since the last scan", name),
				During:  "baseline-diff", Source: "baseline",
				Detail: map[string]any{
					"was":      clip(old.Descriptions[name], 200),
					"now":      clip(current.Descriptions[name], 200),
					"evidence": "description hash changed",
					"since":    old.RecordedAt.Format(time.RFC3339),
				},
			})
		}
	}

	// A tool vanishing is worth a note but not alarm: removals are ordinary
	// maintenance, and treating them as findings would make every legitimate
	// update noisy.
	var removed []string
	for name := range old.Tools {
		if _, still := current.Tools[name]; !still {
			removed = append(removed, name)
		}
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		events = append(events, trace.Event{
			Kind: trace.KindProtocol, Severity: trace.SeverityInfo, At: now,
			Summary: fmt.Sprintf("%d tool(s) removed since the last scan", len(removed)),
			During:  "baseline-diff", Source: "baseline",
			Detail: map[string]any{"evidence": strings.Join(removed, ", ")},
		})
	}

	return events
}

func clip(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "..."
	}
	return s
}

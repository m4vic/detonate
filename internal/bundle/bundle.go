// Package bundle writes an opt-in, bounded record of a Detonate scan.
package bundle

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/m4vic/detonate/internal/report"
	"github.com/m4vic/detonate/internal/termsafe"
)

const (
	SchemaV1             = "detonate.bundle/v1"
	maxTextReportBytes   = 1024 * 1024
	maxJSONReportBytes   = 4 * 1024 * 1024
	maxManifestBytes     = 64 * 1024
	redactionPlaceholder = "[REDACTED]"
)

type Options struct {
	Directory        string
	Target           string
	Version          string
	DetonateCommit   string
	DetonateModified bool
	RepositoryURL    string
	Subpath          string
	Revision         string
	SandboxImage     string
	Report           report.Scan
	Now              time.Time
}

type Provenance struct {
	Detonate DetonateProvenance `json:"detonate"`
	Target   *TargetProvenance  `json:"target,omitempty"`
	Sandbox  *SandboxProvenance `json:"sandbox,omitempty"`
}

type DetonateProvenance struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Modified bool   `json:"modified,omitempty"`
}

type TargetProvenance struct {
	RepositoryURL string `json:"repository_url"`
	Subpath       string `json:"subpath,omitempty"`
	Commit        string `json:"commit"`
}

type SandboxProvenance struct {
	Image string `json:"image"`
}

type Manifest struct {
	Schema     string         `json:"schema"`
	RunID      string         `json:"run_id"`
	Created    time.Time      `json:"created"`
	Tool       string         `json:"tool"`
	Version    string         `json:"version"`
	Target     string         `json:"target"`
	Provenance Provenance     `json:"provenance"`
	Files      []string       `json:"files"`
	Redactions map[string]int `json:"redactions"`
	Truncated  []string       `json:"truncated,omitempty"`
}

var (
	ansiPattern    = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bsk-[a-z0-9_-]{16,}\b`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`),
		regexp.MustCompile(`\bAKIA[A-Z0-9]{16}\b`),
		regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|token|password|secret)\s*[:=]\s*[^\s,;&\"'{}\[\]]+`),
	}
)

// Save writes a complete bundle to a sibling temporary directory and then
// renames it into place. Existing destinations are never overwritten.
func Save(opt Options) (string, error) {
	now := opt.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	runID, err := newRunID()
	if err != nil {
		return "", err
	}
	destination := opt.Directory
	if destination == "" {
		destination = filepath.Join("detonate-results",
			targetSlug(opt.Target)+"-"+now.Format("20060102T150405Z")+"-"+runID)
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return "", fmt.Errorf("resolving bundle path: %w", err)
	}
	if _, err := os.Stat(destination); err == nil {
		return "", fmt.Errorf("bundle destination already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("checking bundle destination: %w", err)
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("creating bundle parent: %w", err)
	}
	temp, err := os.MkdirTemp(parent, ".detonate-bundle-")
	if err != nil {
		return "", fmt.Errorf("creating temporary bundle: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(temp)
		}
	}()

	textReport, textRedactions := redact(printableText(Text(opt.Report)))
	var truncated []string
	if len(textReport) > maxTextReportBytes {
		textReport = strings.ToValidUTF8(textReport[:maxTextReportBytes], "") + "\n...[truncated]\n"
		truncated = append(truncated, "report.txt")
	}

	reportData, jsonRedactions, err := redactedJSON(opt.Report)
	if err != nil {
		return "", fmt.Errorf("encoding report: %w", err)
	}
	if len(reportData) > maxJSONReportBytes {
		return "", fmt.Errorf("report.json exceeds %d-byte bundle limit", maxJSONReportBytes)
	}
	target, targetRedactions := redact(opt.Target)
	repositoryURL, repositoryRedactions := redact(opt.RepositoryURL)
	provenance := Provenance{Detonate: DetonateProvenance{
		Version: opt.Version, Commit: opt.DetonateCommit,
		Modified: opt.DetonateModified,
	}}
	if repositoryURL != "" || opt.Subpath != "" || opt.Revision != "" {
		provenance.Target = &TargetProvenance{
			RepositoryURL: repositoryURL,
			Subpath:       filepath.ToSlash(opt.Subpath),
			Commit:        opt.Revision,
		}
	}
	if opt.SandboxImage != "" {
		provenance.Sandbox = &SandboxProvenance{Image: opt.SandboxImage}
	}
	manifest := Manifest{
		Schema: SchemaV1, RunID: runID, Created: now, Tool: "detonate",
		Version: opt.Version, Target: target, Provenance: provenance,
		Files: []string{"manifest.json", "report.txt", "report.json"},
		Redactions: map[string]int{
			"manifest.json": targetRedactions + repositoryRedactions,
			"report.txt":    textRedactions,
			"report.json":   jsonRedactions,
		},
		Truncated: truncated,
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding bundle manifest: %w", err)
	}
	manifestData = append(manifestData, '\n')
	if len(manifestData) > maxManifestBytes {
		return "", fmt.Errorf("manifest.json exceeds %d-byte bundle limit", maxManifestBytes)
	}

	for name, data := range map[string][]byte{
		"report.txt":    []byte(textReport),
		"report.json":   reportData,
		"manifest.json": manifestData,
	} {
		if err := writeFile(filepath.Join(temp, name), data); err != nil {
			return "", err
		}
	}
	if err := os.Rename(temp, destination); err != nil {
		return "", fmt.Errorf("completing bundle: %w", err)
	}
	complete = true
	return destination, nil
}

// Text renders the portable human view from the same canonical Scan used for
// report.json. It deliberately contains no terminal styling or progress log.
func Text(scan report.Scan) string {
	var out strings.Builder
	// Structural literals stay unsanitized; every target-controlled value between
	// them is cleaned per field (termsafe strips newlines, so it cannot wrap the
	// whole render). This mirrors the live renderer exactly — same package, same
	// call — so a saved bundle cannot inject terminal control on offline replay.
	fmt.Fprintf(&out, "Detonate saved report\n\nTarget: %s\nVersion: %s\nRisk: %s\nCompleteness: %s\n",
		termsafe.Clean(scan.Target), scan.Version, scan.Risk, scan.Completeness)
	fmt.Fprintf(&out, "Findings: %d critical, %d notable\nObservations: %d\nFailures: %d\n",
		scan.Counts.Critical, scan.Counts.Notable, scan.Counts.Info, len(scan.Failures))

	if len(scan.Scenarios) > 0 {
		out.WriteString("\nScenarios:\n")
		for _, scenario := range scan.Scenarios {
			fmt.Fprintf(&out, "- %s: %s", termsafe.Clean(scenario.ID), scenario.Outcome)
			if scenario.Reason != "" {
				fmt.Fprintf(&out, " (%s)", termsafe.Clean(scenario.Reason))
			}
			out.WriteByte('\n')
		}
	}
	if len(scan.Findings) > 0 {
		out.WriteString("\nFindings:\n")
		for _, finding := range scan.Findings {
			fmt.Fprintf(&out, "- [%s] %s", finding.Severity, termsafe.Clean(finding.Summary))
			if finding.Evidence != "" {
				fmt.Fprintf(&out, "\n  Evidence: %s", termsafe.Clean(finding.Evidence))
			}
			out.WriteByte('\n')
		}
	}
	if len(scan.Observations) > 0 {
		out.WriteString("\nObservations:\n")
		for _, observation := range scan.Observations {
			fmt.Fprintf(&out, "- %s\n", termsafe.Clean(observation.Summary))
		}
	}
	if len(scan.Failures) > 0 {
		out.WriteString("\nFailures:\n")
		for _, failure := range scan.Failures {
			fmt.Fprintf(&out, "- %s/%s: %s\n", failure.Phase, failure.Code, termsafe.Clean(failure.Message))
		}
	}
	return out.String()
}

// Load reads the canonical report from a completed bundle. It never follows a
// path from the manifest, which keeps a modified bundle from escaping its own
// directory during an offline re-render.
func Load(directory string) (Manifest, report.Scan, error) {
	var manifest Manifest
	var scan report.Scan
	manifestData, err := readBundleFile(directory, "manifest.json", maxManifestBytes)
	if err != nil {
		return manifest, scan, fmt.Errorf("reading bundle manifest: %w", err)
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return manifest, scan, fmt.Errorf("decoding bundle manifest: %w", err)
	}
	if manifest.Schema != SchemaV1 {
		return manifest, scan, fmt.Errorf("unsupported bundle schema %q", manifest.Schema)
	}
	if !containsFile(manifest.Files, "report.json") {
		return manifest, scan, errors.New("bundle manifest does not include report.json")
	}
	reportData, err := readBundleFile(directory, "report.json", maxJSONReportBytes)
	if err != nil {
		return manifest, scan, fmt.Errorf("reading bundle report: %w", err)
	}
	if err := json.Unmarshal(reportData, &scan); err != nil {
		return manifest, scan, fmt.Errorf("decoding bundle report: %w", err)
	}
	if scan.Schema != report.SchemaV1 {
		return manifest, scan, fmt.Errorf("unsupported report schema %q", scan.Schema)
	}
	return manifest, scan, nil
}

func readBundleFile(directory, name string, limit int) ([]byte, error) {
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", name, limit)
	}
	return os.ReadFile(path)
}

func containsFile(files []string, wanted string) bool {
	for _, name := range files {
		if name == wanted {
			return true
		}
	}
	return false
}

func redactedJSON(scan report.Scan) ([]byte, int, error) {
	raw, err := json.Marshal(scan)
	if err != nil {
		return nil, 0, err
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, 0, err
	}
	count := 0
	document = redactJSONValue(document, &count)
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	return append(data, '\n'), count, nil
}

func redactJSONValue(value any, count *int) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			typed[key] = redactJSONValue(child, count)
		}
	case []any:
		for index, child := range typed {
			typed[index] = redactJSONValue(child, count)
		}
	case string:
		redacted, found := redact(typed)
		*count += found
		return redacted
	}
	return value
}

func writeFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Base(path), err)
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}
	return nil
}

func newRunID() (string, error) {
	var data [4]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("generating bundle run id: %w", err)
	}
	return hex.EncodeToString(data[:]), nil
}

func targetSlug(target string) string {
	target = strings.TrimSuffix(strings.TrimSpace(target), "/")
	base := filepath.Base(strings.ReplaceAll(target, "\\", "/"))
	base = strings.TrimSuffix(base, ".git")
	if base == "" || base == "." {
		base = "scan"
	}
	var out strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(base) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			out.WriteRune(r)
			lastDash = false
		} else if out.Len() > 0 && !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
		if out.Len() >= 48 {
			break
		}
	}
	slug := strings.Trim(out.String(), "-")
	if slug == "" {
		return "scan"
	}
	return slug
}

func printableText(value string) string {
	value = ansiPattern.ReplaceAllString(value, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (unicode.IsPrint(r) && r != '\r') {
			return r
		}
		return -1
	}, strings.ToValidUTF8(value, "?"))
}

func redact(value string) (string, int) {
	count := 0
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllStringFunc(value, func(match string) string {
			count++
			if index := strings.IndexAny(match, ":="); index >= 0 {
				return match[:index+1] + redactionPlaceholder
			}
			return redactionPlaceholder
		})
	}
	return value, count
}

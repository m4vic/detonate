package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// ReapOrphans removes containers left behind by earlier detonate runs and
// returns how many it destroyed.
//
// Close() guarantees teardown for a scan that ends normally, but nothing can
// guarantee it for one that does not: SIGKILL, a power loss, or a panic in our
// own code all leave a container running with no client attached. For a tool
// whose whole promise is that untrusted code does not outlive the scan, a
// best-effort guarantee is not enough — there has to be something that cleans
// up after the case where the guarantee failed.
//
// This is why every container is named with NamePrefix. The prefix is the only
// thing that survives a hard kill, so it is what makes orphans identifiable
// afterwards.
//
// Errors are deliberately not returned. Reaping is opportunistic housekeeping
// at startup; a docker hiccup here must not fail a scan that would otherwise
// have worked.
func ReapOrphans(ctx context.Context) int {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, dockerBinary,
		"ps", "-aq", "--filter", "name="+NamePrefix).Output()
	if err != nil {
		return 0
	}

	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return 0
	}

	// One rm for all of them: N docker invocations would make startup latency
	// scale with how badly the last run crashed.
	args := append([]string{"rm", "-f"}, ids...)
	if err := exec.CommandContext(ctx, dockerBinary, args...).Run(); err != nil {
		return 0
	}
	return len(ids)
}

package cli

import (
	"context"
	"fmt"
	"runtime"

	"github.com/m4vic/detonate/internal/acquire"
	"github.com/m4vic/detonate/internal/sandbox"
)

// doctor reports whether this machine can run a scan, and what it cannot.
//
// It exists because the first failure a new user hits is environmental, and the
// error they get is from the middle of a scan. A missing Docker daemon
// surfaced as a runtime failure partway through a pipeline reads like the tool
// is broken; the same fact reported up front, with the command that fixes it,
// reads like a checklist.
//
// It deliberately reports what still WORKS without Docker. Prompt and skill
// analysis need no container, and a user who believes the whole tool is
// unavailable will not try the half that would have helped them.
func (a *App) doctor(ctx context.Context) int {
	fmt.Fprintf(a.Stdout, "detonate %s  %s/%s\n\n", Version, runtime.GOOS, runtime.GOARCH)

	ready := true

	// Docker is the sandbox. Without it nothing untrusted may execute, which is
	// a refusal rather than a degradation: running a target on the host to be
	// helpful would defeat the only guarantee this tool makes.
	status := a.CheckDocker(ctx)
	switch {
	case status.Ready():
		fmt.Fprintf(a.Stdout, "  [ok]   docker            %s\n", status.Detail)
	case status.Installed:
		ready = false
		fmt.Fprintf(a.Stdout, "  [FAIL] docker daemon     %s\n", status.Detail)
		fmt.Fprintln(a.Stdout, "         start Docker Desktop, or: sudo systemctl start docker")
	default:
		ready = false
		fmt.Fprintf(a.Stdout, "  [FAIL] docker            %s\n", status.Detail)
		fmt.Fprintln(a.Stdout, "         install it: https://docs.docker.com/get-docker/")
	}

	// Images are checked only when the daemon can answer. Asking a dead daemon
	// about images produces a second failure with the same cause, which buries
	// the one line the user actually needs.
	if status.Ready() {
		for _, image := range []string{acquire.PythonImage, acquire.NodeImage} {
			if sandbox.ImagePresent(ctx, image) {
				fmt.Fprintf(a.Stdout, "  [ok]   image             %s\n", image)
				continue
			}
			// Not a failure. A missing image costs the first scan a download,
			// it does not stop it, and reporting it as broken would send the
			// user looking for a problem that does not exist.
			fmt.Fprintf(a.Stdout, "  [warn] image             %s not downloaded yet\n", image)
			fmt.Fprintf(a.Stdout, "         the first scan will pull it, or: docker pull %s\n", image)
		}
	}

	fmt.Fprintln(a.Stdout)
	if ready {
		fmt.Fprintln(a.Stdout, "  Ready. Try:  detonate ./some-mcp-server")
		return exitOK
	}

	fmt.Fprintln(a.Stdout, "  Docker is unavailable, so no target can be executed.")
	fmt.Fprintln(a.Stdout, "  These still work, because they read text rather than run it:")
	fmt.Fprintln(a.Stdout, "    detonate static ./skills/some-skill")
	fmt.Fprintln(a.Stdout, "    detonate static ./system-prompt.txt")
	fmt.Fprintln(a.Stdout, "    echo \"ignore all previous instructions\" | detonate -")
	return exitUsage
}

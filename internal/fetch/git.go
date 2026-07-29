// Package fetch acquires a target from a remote source.
//
// Cloning happens on the HOST, deliberately, and that is worth justifying in a
// tool whose whole premise is that untrusted code runs in a container.
//
// `git clone` does not execute the cloned repository. It writes files. The
// exception is a repo carrying hooks, and hooks in .git/hooks are never run by
// a clone — only by later git operations we do not perform. So the risk here
// is writing files to a temp directory, which is the same risk as downloading
// a zip.
//
// What we do NOT do is run anything from the clone. That still happens only
// inside the sandbox, after this package hands back a path.
package fetch

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const cloneTimeout = 5 * time.Minute

// Result is a fetched target on local disk.
type Result struct {
	// Dir is where the target was written.
	Dir string

	// Source is the URL it came from, for the report.
	Source string

	// cleanup removes the temp directory.
	cleanup func()
}

// Cleanup removes the fetched copy. Safe to call more than once.
func (r *Result) Cleanup() {
	if r.cleanup != nil {
		r.cleanup()
		r.cleanup = nil
	}
}

// Git clones a repository into a temporary directory.
//
// Shallow (--depth 1) because a scan cares about what the code does now, not
// how it got here, and a full history on a large repo is a slow surprise.
func Git(ctx context.Context, rawURL string) (*Result, error) {
	normalized, err := normalizeGitURL(rawURL)
	if err != nil {
		return nil, err
	}

	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("git is not installed; clone %s manually and use --dir", normalized)
	}

	dir, err := os.MkdirTemp("", "detonate-clone-")
	if err != nil {
		return nil, fmt.Errorf("creating temp directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	ctx, cancel := context.WithTimeout(ctx, cloneTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--quiet", normalized, dir)
	// Refuse credential prompts. Without this a private repo hangs the scan
	// waiting for a password nobody is there to type, which in CI is a job
	// that never ends.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=echo")

	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		cleanup()
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return nil, fmt.Errorf("cloning %s: %s", normalized, truncate(detail, 300))
	}

	return &Result{Dir: dir, Source: normalized, cleanup: cleanup}, nil
}

// normalizeGitURL accepts the shorthand people actually paste.
//
// "github.com/user/repo" and a full https URL should both work, because the
// alternative is a tool that rejects the exact string a user copied out of
// their browser.
func normalizeGitURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty git URL")
	}
	s = strings.TrimSuffix(s, "/")

	// Already a full URL or an SSH remote.
	if strings.Contains(s, "://") || strings.HasPrefix(s, "git@") {
		return s, nil
	}

	// Bare host/owner/repo shorthand.
	if strings.Count(s, "/") >= 2 {
		return "https://" + s, nil
	}
	return "", fmt.Errorf("cannot interpret %q as a git URL; try https://github.com/owner/repo", raw)
}

// SubDir resolves a path inside a fetched repo, refusing to escape it.
//
// Needed because skill packs nest their skills, so a user will reasonably want
// --git <repo> --path skills/foo. The traversal check exists because that path
// comes from the command line and joining it blindly would let "../.." reach
// outside the clone.
func (r *Result) SubDir(rel string) (string, error) {
	if rel == "" {
		return r.Dir, nil
	}
	joined := filepath.Join(r.Dir, filepath.FromSlash(rel))

	abs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(r.Dir)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(abs, root) {
		return "", fmt.Errorf("--path %q escapes the cloned repository", rel)
	}
	if info, err := os.Stat(abs); err != nil || !info.IsDir() {
		return "", fmt.Errorf("--path %q does not exist in the repository", rel)
	}
	return abs, nil
}

// IsURL reports whether a string looks like something Git can clone, so the
// CLI can accept a URL where it accepts a path without a separate flag.
func IsURL(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "git@") {
		return true
	}
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		return true
	}
	// host/owner/repo with a dot in the host.
	parts := strings.Split(s, "/")
	return len(parts) >= 3 && strings.Contains(parts[0], ".")
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

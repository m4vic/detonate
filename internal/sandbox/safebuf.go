package sandbox

import (
	"strings"
	"sync"
)

// safeBuffer is an io.Writer that can be read while it is being written.
//
// This exists because of a real bug. cmd.Stderr was a strings.Builder, which
// os/exec fills from its own copier goroutine while callers read it via
// Stderr(). That is an unsynchronised concurrent access: a reader could
// observe an empty buffer even after the container had written to it.
//
// The consequence was specific and bad. detonate's whole verdict for a
// blocked network call comes from the target's stderr, so losing that read
// means reporting "no suspicious behaviour observed" for a server that just
// tried to phone home. A security tool silently downgrading a finding to
// silence is the worst failure mode available to it.
//
// It hid well, too: the CLI reads stderr once at the end, after the session
// has closed, where the race rarely loses. Only reading DURING the run — as
// the monitor's tests do — exposed it.
type safeBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns everything written so far. Safe to call at any time,
// including while the container is still running.
func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

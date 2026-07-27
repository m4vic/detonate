package mcpdriver

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/m4vic/detonate/internal/mcptest"
)

// These tests are the dynamic half of detonate's own test suite: real hostile
// server processes, launched over real pipes, doing the things a malicious MCP
// server actually does. Static tests prove we parse a manifest. These prove we
// survive the server.
//
// The property under test is the same in every case: EnumerateTools must
// return within its timeout, and must not leave a process running. A scanner
// that hangs reports nothing, and "nothing" is indistinguishable from "clean".

// assertBounded runs fn and fails if it outlives limit. Without this the
// failure mode of a hang test is the whole suite hanging, which is exactly the
// bug being tested, just relocated.
func assertBounded(t *testing.T, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("EnumerateTools did not return within %s", limit)
	}
}

func TestHostileServerHangs(t *testing.T) {
	// A server that accepts the connection and then never speaks. Our timeout
	// is the only thing that ends this.
	const budget = 3 * time.Second

	assertBounded(t, 20*time.Second, func() {
		start := time.Now()
		_, err := EnumerateTools(context.Background(),
			mcptest.HostileCommand(mcptest.BehaviourHang), budget)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("a server that never answers must not produce a successful scan")
		}

		// Assert the timeout is what ended this, not an EOF.
		//
		// An earlier version of the fixture used `select{}`, which made the Go
		// runtime panic on deadlock and kill the process. The client saw an
		// immediate EOF, the test passed in 330ms, and it was really just
		// testing BehaviourCrash a second time. Requiring the deadline error
		// AND the elapsed time is what stops that from recurring silently.
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("want context.DeadlineExceeded, got %v\n"+
				"(the server died on its own instead of hanging)", err)
		}
		if elapsed < budget {
			t.Errorf("returned in %s, before the %s budget elapsed; "+
				"the server cannot have been hanging", elapsed, budget)
		}
		if elapsed > budget+10*time.Second {
			t.Errorf("timeout not respected: took %s for a %s budget", elapsed, budget)
		}
	})
}

func TestHostileServerCrashes(t *testing.T) {
	assertBounded(t, 20*time.Second, func() {
		_, err := EnumerateTools(context.Background(),
			mcptest.HostileCommand(mcptest.BehaviourCrash), 10*time.Second)
		if err == nil {
			t.Error("a server that exits immediately must be reported as a failure")
		}
	})
}

func TestHostileServerWritesGarbage(t *testing.T) {
	// Non-JSON-RPC noise on stdout must fail cleanly, not panic and not be
	// mistaken for a tool list.
	assertBounded(t, 20*time.Second, func() {
		tools, err := EnumerateTools(context.Background(),
			mcptest.HostileCommand(mcptest.BehaviourGarbage), 5*time.Second)
		if err == nil {
			t.Errorf("garbage on stdout must not yield a successful scan, got %d tools", len(tools))
		}
	})
}

func TestHostileServerSlowHandshake(t *testing.T) {
	// The server initializes eventually, but far past our budget. This checks
	// the timeout covers the whole launch-handshake-list sequence rather than
	// only the spawn.
	assertBounded(t, 20*time.Second, func() {
		start := time.Now()
		_, err := EnumerateTools(context.Background(),
			mcptest.HostileCommand(mcptest.BehaviourSlowHandshake), 2*time.Second)
		if err == nil {
			t.Error("a handshake slower than the timeout must fail the scan")
		}
		if elapsed := time.Since(start); elapsed > 15*time.Second {
			t.Errorf("timeout not enforced across the handshake: took %s", elapsed)
		}
	})
}

// The safety-critical one. A server that ignores its closed stdin must still
// be dead when the scan returns, or detonate has left untrusted code running
// on the host it was supposed to protect.
func TestHostileServerIgnoringEOFIsKilled(t *testing.T) {
	before := countProcesses(t)

	assertBounded(t, 30*time.Second, func() {
		_, err := EnumerateTools(context.Background(),
			mcptest.HostileCommand(mcptest.BehaviourIgnoreEOF), 10*time.Second)
		if err != nil {
			t.Logf("enumeration error (acceptable, teardown is what matters): %v", err)
		}
	})

	// Teardown escalates through a grace period, so allow it time to land
	// before concluding the process leaked.
	deadline := time.Now().Add(3 * teardownGrace)
	for time.Now().Before(deadline) {
		if countProcesses(t) <= before {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Errorf("server process outlived the scan: %d test processes before, %d after",
		before, countProcesses(t))
}

func TestHostileServerPoisonedDescription(t *testing.T) {
	// A prompt-injection payload in a tool description is valid protocol, so
	// enumeration must SUCCEED and preserve the payload verbatim. Truncating
	// or sanitising here would destroy the evidence the report is built on.
	assertBounded(t, 20*time.Second, func() {
		tools, err := EnumerateTools(context.Background(),
			mcptest.HostileCommand(mcptest.BehaviourPoisoned), 10*time.Second)
		if err != nil {
			t.Fatalf("a poisoned but well-formed server must still enumerate: %v", err)
		}
		if len(tools) != 1 {
			t.Fatalf("got %d tools, want 1", len(tools))
		}
		desc := tools[0].Description
		for _, marker := range []string{"IMPORTANT", "id_rsa", "Do not mention"} {
			if !strings.Contains(desc, marker) {
				t.Errorf("payload marker %q missing; the description was altered", marker)
			}
		}
	})
}

func TestHostileServerHugeDescription(t *testing.T) {
	// A 1 MiB description must not hang or blow up. It also must not be
	// truncated in the struct: only the CLI's one-line String() clips.
	assertBounded(t, 30*time.Second, func() {
		tools, err := EnumerateTools(context.Background(),
			mcptest.HostileCommand(mcptest.BehaviourHugeDescription), 15*time.Second)
		if err != nil {
			t.Fatalf("large description should not fail enumeration: %v", err)
		}
		if got := len(tools[0].Description); got < 1<<20 {
			t.Errorf("description truncated in transit: got %d bytes, want >= %d", got, 1<<20)
		}
		if line := tools[0].String(); len(line) > 200 {
			t.Errorf("String() must clip for display, got %d chars", len(line))
		}
	})
}

// countProcesses counts running instances of this test binary. Used to detect
// a server that outlived its scan.
func countProcesses(t *testing.T) int {
	t.Helper()
	if runtime.GOOS != "windows" {
		// pgrep counts matching processes; absence of the tool is not a test
		// failure, it just means this check is a no-op on that machine.
		out, err := exec.Command("pgrep", "-c", "-f", "detonate-hostile").Output()
		if err != nil {
			return 0
		}
		n := 0
		_, _ = fmtSscan(strings.TrimSpace(string(out)), &n)
		return n
	}

	out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq mcpdriver.test.exe", "/NH").Output()
	if err != nil {
		return 0
	}
	return strings.Count(string(out), "mcpdriver.test.exe")
}

// fmtSscan is a tiny indirection so the non-Windows branch above doesn't pull
// fmt into this file's imports on Windows builds.
func fmtSscan(s string, n *int) (int, error) {
	total := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		total = total*10 + int(r-'0')
	}
	*n = total
	return 1, nil
}

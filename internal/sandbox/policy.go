// Package sandbox runs untrusted code inside a disposable container.
//
// This is the package detonate exists for. Every other MCP scanner reads a
// server's manifest and reasons about what it claims. detonate runs it and
// watches what it does — and running untrusted code is only defensible if the
// box around it is real.
//
// The container is not primarily a safety blanket. It is the OBSERVATION
// INSTRUMENT: a boundary where every packet, file and process crossing it can
// be seen. Without that boundary there is no vantage point, and detonate would
// just be another description-reader.
package sandbox

import "time"

// Policy is the confinement applied to a sandboxed target.
//
// Every field here is a security decision, kept in one small struct on purpose
// so the whole posture can be reviewed at once rather than reconstructed from
// scattered flags. Anything that weakens the box should be visible in a diff
// of this file.
type Policy struct {
	// Image is the base filesystem the target runs on. Pinned by digest in
	// production: a floating tag means the sandbox silently changes under you,
	// and a scanner whose environment drifts produces findings that cannot be
	// reproduced.
	Image string

	// Network off is the single most valuable control detonate has. An MCP
	// server with no route out cannot exfiltrate, cannot fetch a second-stage
	// payload, and cannot phone home. When a probe later tries to reach the
	// network, the attempt itself is the finding.
	NetworkEnabled bool

	// ReadOnlyRootfs stops a target persisting anything to its own image
	// layer. Combined with a tmpfs at /tmp, a server that needs scratch space
	// still works, but nothing it writes survives the scan.
	ReadOnlyRootfs bool

	// MemoryBytes and PidLimit bound the two cheapest denial-of-service moves
	// available to hostile code: allocate until the host swaps, or fork until
	// the process table is full. Both would take down the machine running the
	// scan, which is a bad outcome for a security tool.
	MemoryBytes int64
	PidLimit    int64

	// CPUShares is relative weight, not a hard cap. A target that spins is
	// throttled rather than killed, because a busy loop is behaviour worth
	// observing, not a reason to abort.
	CPUShares int64

	// User is the uid:gid the target runs as. Never root: a root process
	// inside a container is one kernel bug away from being root outside it.
	User string

	// Timeout bounds the container's whole life. Nothing untrusted runs
	// unbounded, including code that looks cooperative right up until it
	// doesn't.
	Timeout time.Duration
}

// DefaultPolicy is the posture every scan gets unless deliberately relaxed.
//
// The defaults are the strict ones. That is the entire differentiator: the one
// competing tool that executes MCP servers ships a
// --dangerously-run-mcp-servers flag and tells the user to sandbox it
// themselves. Here, safe is what you get for free and weakening it is the
// thing you have to ask for.
func DefaultPolicy() Policy {
	return Policy{
		Image:          DefaultImage,
		NetworkEnabled: false,
		ReadOnlyRootfs: true,
		MemoryBytes:    512 * 1024 * 1024, // 512 MiB
		PidLimit:       128,
		CPUShares:      512, // half of Docker's 1024 default
		User:           "1000:1000",
		Timeout:        60 * time.Second,
	}
}

// DefaultImage is the sandbox base image.
//
// Python and Node are present because that is what real MCP servers are
// written in; a sandbox that cannot run the ecosystem is a sandbox nobody
// uses. Pin this to a digest before the first release.
const DefaultImage = "python:3.12-slim"

// dropAllCapabilities removes every Linux capability from the container.
//
// A default Docker container keeps around a dozen, including CAP_CHOWN and
// CAP_SETUID. None of them are needed to speak JSON-RPC over a pipe, and each
// is a rung on a privilege-escalation ladder. Dropping all and adding none is
// the correct posture for code we assume is hostile.
var dropAllCapabilities = []string{"ALL"}

// securityOptions are passed to the container runtime directly.
//
// no-new-privileges blocks the setuid path to gaining privileges mid-run, so a
// target cannot escalate even if it ships a setuid binary.
var securityOptions = []string{"no-new-privileges"}

// tmpfsMounts give the target somewhere writable without letting anything
// persist. Backed by memory, capped, and discarded when the container dies.
// noexec matters: a server that drops a payload into /tmp cannot then run it.
var tmpfsMounts = map[string]string{
	"/tmp": "rw,noexec,nosuid,size=64m",
}

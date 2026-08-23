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

	// TmpfsSize is how much scratch space the target gets at /tmp.
	//
	// Configurable because the two phases need wildly different amounts. The
	// detonation phase wants this small: a target has no legitimate reason to
	// write hundreds of megabytes while its tools are being listed. The
	// install phase needs far more, because pip and npm unpack and build in
	// /tmp — at the detonation default a real server fails with "No space left
	// on device" before it is ever scanned.
	TmpfsSize string

	// Env are environment variables for the target process.
	//
	// This is runtime configuration, not security posture — it exists so the
	// detonation phase can point an interpreter at dependencies installed in a
	// separate, earlier container (PYTHONPATH, NODE_PATH). Never put secrets
	// here: the target reads its own environment, so anything placed in it is
	// handed directly to untrusted code.
	Env map[string]string

	// NetworkProxy, when set, routes the container's traffic through an
	// intercepting proxy rather than applying --network none. This allows
	// MCP servers that require network access to run while still monitoring
	// outbound requests for data exfiltration (e.g. canary tokens leaking
	// to an external host). Empty means strict network-off (default).
	//
	// Not yet implemented: this field is a configuration placeholder for the
	// v1.0.0 intercepting-proxy feature.
	NetworkProxy string
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
		TmpfsSize:      "64m",
	}
}

// DefaultImage is the sandbox base image.
//
// Python and Node are present because that is what real MCP servers are
// written in; a sandbox that cannot run the ecosystem is a sandbox nobody
// uses. Pin this to a digest before the first release.
const DefaultImage = "python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"

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

// tmpfsMounts gives the target somewhere writable without letting anything
// persist. Backed by memory, capped, and discarded when the container dies.
//
// noexec is the security-relevant part: a server that drops a payload into
// /tmp cannot then run it. It stays set in every phase, including install.
func tmpfsMounts(size string) map[string]string {
	if size == "" {
		size = "64m"
	}
	return map[string]string{
		"/tmp": "rw,noexec,nosuid,size=" + size,

		// A writable HOME, and the reason is calibration rather than
		// convenience.
		//
		// Most MCP servers store state under ~/.something on startup. With no
		// writable home, every one of them fails a write and gets reported as
		// "attempted a write the sandbox denied" — a finding about our
		// environment, not their behaviour. Scanning a real server surfaced
		// exactly that: it tried to create ~/.ctx and, with HOME unset,
		// resolved to /.ctx at the read-only root.
		//
		// Giving targets a realistic home makes writing there unremarkable and
		// turns a write ANYWHERE ELSE back into a real signal. Still a tmpfs:
		// nothing survives the container, and noexec means a payload dropped
		// here cannot be run.
		containerHome: "rw,noexec,nosuid,size=" + size,
	}
}

// ContainerHome is the home directory given to a sandboxed target.
//
// Exported because a caller that furnishes a decoy has to mount it exactly
// here: mounting anywhere else would leave the empty tmpfs home in place and
// the target would never find the planted secrets.
const ContainerHome = "/home/detonate"

// containerHome is the unexported alias the rest of this package already used.
const containerHome = ContainerHome

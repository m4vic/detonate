# detonate — Architecture

This document is the map of how detonate works and *why* it is built this way.
It is kept current with the code — when the design changes, this file changes in
the same commit. (If you are following the build on video, this is the file to
read first.)

---

## The one idea

Every other MCP/skill scanner **reads** the tool — its manifest, its tool
descriptions, its source. detonate **runs** it, inside a disposable sandbox, and
watches what it actually does. "Detonation chamber" is the malware-analysis term
for exactly this: put the suspicious thing in an isolated box and observe.

Why this matters: a manifest describes *intent*. Behavior reveals *reality*. A
server can declare an innocent `read_file` tool and, when invoked, try to read
`/etc/shadow` or phone home. Static scanning cannot see that. Detonation can.

---

## The core safety rule

**detonate never runs untrusted code outside a sandbox.** This is not a feature,
it is the precondition for the tool existing. Concretely:

- Every scan is gated by a Docker pre-flight check (`internal/environment`). No
  Docker, no scan — it stops with an actionable message instead of running
  anything.
- A scan never returns while the code it launched may still be running. The MCP
  driver closes the session, waits for the process to die, and escalates to a
  kill if it doesn't. A verdict delivered while its subject is still alive is
  not a finished scan.
- The untrusted MCP server is launched *inside* a disposable container with
  network off by default, a restricted filesystem, and resource limits.

This is the exact gap in the market: the one execution-based competitor (Snyk
Agent Scan) executes servers but ships a `--dangerously-run-mcp-servers` flag and
tells the user to sandbox it themselves. detonate sandboxes by default.

---

## The pipeline

```
detonate scan --mcp "<command that launches the server>"
      │
      ▼  ┌──────────────────────────────────────────────────────────┐
      │  │ Static pre-check  (cheap, no execution)                  │  M6
      │  │   grep tool descriptions/manifest for known bad patterns │
      │  └──────────────────────────────────────────────────────────┘
      ▼  ┌──────────────────────────────────────────────────────────┐
      │  │ Sandbox           (Docker)                               │  M2
      │  │   disposable container: net off, fs restricted, limited  │
      │  └──────────────────────────────────────────────────────────┘
      ▼  ┌──────────────────────────────────────────────────────────┐
      │  │ MCP driver        (official MCP Go SDK)                  │  M1
      │  │   connect over stdio INSIDE the sandbox, enumerate tools │
      │  └──────────────────────────────────────────────────────────┘
      ▼  ┌──────────────────────────────────────────────────────────┐
      │  │ Probe + Monitor   ("detonation")                         │  M3+M4
      │  │   invoke each tool with adversarial args WHILE watching  │
      │  │   egress attempts / fs writes / process spawns           │
      │  └──────────────────────────────────────────────────────────┘
      ▼  ┌──────────────────────────────────────────────────────────┐
      │  │ Verdict + evidence                                       │  M5
      │  │   safe / suspicious / dangerous  + concrete evidence     │
      │  └──────────────────────────────────────────────────────────┘
      ▼
   JSON / SARIF / Markdown                                             M7
```

---

## Why Go

detonate was prototyped in Python (M0-M1) and ported to Go before the sandbox
landed. The prototype is kept under `archive/` rather than deleted.

What detonate actually does, mechanically: spawn subprocesses and speak
JSON-RPC over stdio, drive the Docker API, tail a high-volume event stream,
enforce a deadline and guaranteed teardown on every step, emit JSON and SARIF.
There is no numerical computing and no ML anywhere in that list, which is
where Python earns its keep.

| Reason | Detail |
|---|---|
| Ecosystem | Docker, containerd and runc are Go. The canonical Docker client is Go; `docker-py` is the port. M2 is container orchestration. |
| Distribution | One static ~9 MB binary, cross-compiled, no runtime to install. Every comparable scanner (trivy, grype, syft, nuclei, gitleaks) is Go for this reason. |
| Cancellation | `context.Context` is stdlib, and "deadline + guaranteed teardown" is detonate's core semantic on every probe, session and container. |
| Protocol | The official MCP Go SDK is stable at v1.x, maintained with Google, and supports stdio. |

**Why not Rust.** Rust's decisive advantage is memory safety when parsing
hostile input *in your own address space*. detonate's design puts untrusted
code on the far side of a container boundary: the malicious server runs in the
sandbox, and our process only ever sees JSON that crossed a pipe. That threat
model removes most of the benefit. Rust would win on an eBPF monitor, but Go
has `cilium/ebpf`, which is what Cilium and Falco actually ship.

**Where Python stays.** ASRT and SafetyDiff are ML-adjacent (transformers,
datasets, judge models) and remain Python. detonate does not import them. If
the two ever need to meet, it is over a process boundary and JSON on stdout,
never FFI.

---

## Module layout

```
cmd/detonate/         # main(): ~4 lines, so nothing untested lives here
internal/
├── cli/              # flag parsing, command dispatch, output
├── target/           # what we scan (mcp | skill)
├── environment/      # Docker pre-flight check (the safety gate)
├── toolinfo/         # the normalized shape both drivers produce
├── mcpdriver/        # MCP stdio session + tool enumeration
├── skill/            # SKILL.md frontmatter + bundled scripts
└── mcptest/          # a real MCP server, for our own tests
archive/              # the Python M0-M1 prototype, kept for reference
```

Two conventions worth stating, because they are what keep the pipeline
testable as it grows:

- **`cli.App` holds its dependencies as fields**, so tests substitute the
  Docker check and drive real scans without a daemon. Otherwise the safety
  gate would make every interesting path untestable on a normal machine.
- **`internal/mcptest` is a real server, not a mock.** The compiled test binary
  re-execs itself as an MCP server over a real stdio pipe, so a green test
  means the protocol works rather than that the function names match.

Packages arrive with their milestone — `sandbox/`, `probes/`, `monitor/`,
`analysis/`, `report/` land as M2-M7 do, each in its own commit, each
documented here as it appears.

---

## Milestone status

- [x] **M0** — Scaffold + Docker pre-flight + runnable `detonate scan`
- [x] **M1** — MCP driver + skill loader (enumerate tools, no sandbox yet)
- [ ] **M2** — Sandbox (run the server inside a disposable container)
- [ ] **M3** — Behavioral monitor (coarse: egress / fs / process)
- [ ] **M4** — Adversarial probes (the detonation)
- [ ] **M5** — Verdict + evidence
- [ ] **M6** — Static pre-check tier
- [ ] **M7** — JSON / SARIF / Markdown output
- [ ] **M8** — Package + CI + first release

---

## What detonate is NOT (scope discipline)

- Not a static manifest reader — that space is crowded (mcp-scan, MCPSafe, Cisco).
- Not a runtime proxy — it tests before/around use, it does not sit in the live
  request path.
- Not part of ASRT or SafetyDiff — separate tool, separate repo, though it shares
  the "run it and observe, don't guess" philosophy.

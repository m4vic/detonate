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

- Every scan is gated by a Docker pre-flight check (`environment.py`). No Docker,
  no scan — it stops with an actionable message instead of running anything.
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
      │  │ Sandbox           (docker-py)                            │  M2
      │  │   disposable container: net off, fs restricted, limited  │
      │  └──────────────────────────────────────────────────────────┘
      ▼  ┌──────────────────────────────────────────────────────────┐
      │  │ MCP driver        (official `mcp` SDK)                    │  M1
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

## Why each language, per component

detonate is intentionally cross-language: each piece uses the tool that fits it,
not one language everywhere.

| Component | Language | Reason |
|---|---|---|
| CLI (M0) | Python (stdlib `argparse`) | Zero deps, runs everywhere, teaches cleanly |
| Environment check (M0) | Python (`subprocess` → docker CLI) | A liveness check needs no SDK |
| MCP driver (M1) | Python (`mcp` SDK) | The official SDK is Python; don't reinvent JSON-RPC |
| Sandbox (M2) | Python (`docker-py`) | Mature SDK; orchestration is I/O-bound, Rust speed adds nothing |
| Probe + coarse monitor (M3-M4) | Python | Payload logic + drives the driver |
| Verdict (M5) | Python | Logic; not a hot path yet |
| **eBPF fine-grained monitor** (phase 2) | **Rust** (`aya`) | Kernel-level tracing — genuine native territory |
| **Distributable CLI/TUI shell** (phase 2) | **Rust** (`clap`+`ratatui`) | Single fast binary; wraps the Python engine over stdin/stdout JSON |

The rule: **Python for the engine and orchestration; Rust where it genuinely
wins** (kernel tracing, a shipped single binary). Not dogma in either direction.

---

## Module layout

```
src/detonate/
├── __init__.py       # version + package docstring
├── __main__.py       # enables `python -m detonate`
├── cli.py            # argparse CLI; command dispatch
└── environment.py    # Docker pre-flight check (the safety gate)
```

Modules arrive with their milestone — `sandbox/`, `mcp` driver, `probes/`,
`monitor/`, `analysis/`, `report/` are added as M1-M7 land, each in its own
commit, each documented here as it appears.

---

## Milestone status

- [x] **M0** — Scaffold + Docker pre-flight + runnable `detonate scan`
- [ ] **M1** — MCP driver (enumerate tools, no sandbox yet)
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

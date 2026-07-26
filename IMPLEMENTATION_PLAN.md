# detonate — Implementation Plan (sandbox-first)

**What it is:** an open-source CLI that *detonates* untrusted AI-connected tools
inside a sandbox and reports what they **actually do** — not what their manifest
claims. "Detonation chamber" is the malware-analysis term for exactly this: run
the suspicious thing in isolation and watch its behavior.

**v1 input types (both execute → both use the one sandbox pipeline):**
- **MCP servers** — launched over stdio, tools enumerated and probed live.
- **Agent skills** (SKILL.md + bundled scripts) — scripts run in the sandbox,
  behavior watched.

Deliberately deferred: raw prompts (text-only — a different, non-sandbox path,
not worth splitting the pipeline for in v1) and GitHub repos/packages (the hard
case — no clean entry point, may need a build step or credentials). Both are
phase 2. Keeping v1 to executable inputs means **one pipeline, not two.**

**The verified gap this fills (three searches confirmed it):** every shipping
competitor either reads the manifest statically (mcp-scan, MCPSafe, Cisco) or
executes **without** a sandbox and makes the user isolate it themselves (Snyk
Agent Scan ships `--dangerously-run-mcp-servers`). **detonate sandboxes by default
and probes adversarially.** That is the entire reason this tool should exist —
so it is built FIRST, not bolted on. A static-only v0.1 was explicitly rejected:
it would just be a sixth entrant in a crowded space.

**License:** Apache-2.0 (patent grant; category standard). Confirm before commit.

---

## Language: best tool per component (not dogmatic)

Sandbox-first pushes the MVP toward Python for concrete reasons, and reserves Rust
for where it genuinely wins:

| Component | Language | Why |
|---|---|---|
| MCP protocol driver | **Python** | Official `mcp` SDK is Python — hand-rolling JSON-RPC in Rust is wasted effort |
| Sandbox orchestration | **Python** | `docker-py` is mature; orchestration is I/O-bound (waiting on containers), Rust speed buys nothing |
| Adversarial probes | **Python** | Payload logic + drives the MCP driver |
| Coarse behavioral monitor (MVP) | **Python** | Reads container events/violations; fast enough for MVP |
| Static pre-checks | **Python** | Trivial pattern-matching; Python fine at MVP scale |
| Verdict / correlation | **Python** | Logic; Rust only if trace volume explodes |
| **Fine-grained eBPF monitor** (phase 2) | **Rust** (`aya`) | Genuine native/kernel territory — the real Rust hot-path |
| **Distributable CLI/TUI shell** (phase 2) | **Rust** (`clap`+`ratatui`) | Single-binary, fast, polished; wraps the working Python engine |

MVP engine is Python. Rust slots in for eBPF and the shipped binary once the
engine works — not before.

---

## Hard dependency (state in README day one)

**Docker must be installed and running.** There is no safe way to detonate
untrusted code without OS-level isolation, so `pip install detonate` alone is not
enough — the user needs Docker. Fine for a dev-tool audience; must be stated
plainly so it is never a surprise.

---

## Architecture

```
detonate scan --mcp <server-command-or-url>
      │
      ▼  (Python)
┌──────────────────────┐
│  Static pre-check    │  cheap tier: grep manifest/tool descriptions for
│  (fast, no exec)     │  poisoning/injection patterns before detonating
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Sandbox             │  disposable Docker container: network OFF by default,
│  (docker-py)         │  restricted fs, resource-limited
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  MCP driver          │  connect (stdio) INSIDE the sandbox, enumerate tools
│  (official mcp SDK)  │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Probe + Monitor     │  invoke each tool with adversarial args WHILE watching
│  (this is the        │  egress attempts / fs writes / process spawns
│   "detonation")      │  ← the thing no competitor does by default
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Verdict + evidence  │  correlate static + dynamic → safe/suspicious/dangerous
│                      │  with concrete evidence (which probe, what it did, trace)
└──────────┬───────────┘
           ▼
     JSON / SARIF / Markdown output
```

**Verdict model:** `safe` / `suspicious` / `dangerous`, each with attached
**evidence** — never a bare score. This is the fix for alert-fatigue: a verdict a
human acts on in one read, receipts underneath.

---

## Milestones (sandbox-first; each demoable; smoke-test before next)

**M0 — Scaffold** · CLI skeleton, `pyproject.toml`, Apache-2.0 LICENSE, README
(with the Docker requirement), `detonate --help`. Docker-availability check on
startup with a clear error if missing.

**M1 — MCP driver (no sandbox yet)** · Using the official `mcp` Python SDK:
connect to a stdio MCP server, enumerate its tools, print them. Proves protocol
handling against a real known-good server.

**M2 — Sandbox (the differentiator foundation)** · Run the MCP server *inside* a
disposable Docker container: network off by default, restricted fs, resource
limits. Enumerate tools from inside. This is "sandboxed by default" made real.

**M3 — Behavioral monitor (coarse)** · During a run, capture egress attempts, fs
writes outside declared scope, process spawns. Coarse but real — the evidence
static scanning cannot produce.

**M4 — Adversarial probes (detonation)** · Invoke each enumerated tool with a
curated set of adversarial inputs (injection strings, path-traversal args,
SSRF-style URLs) UNDER M2 sandbox + M3 monitoring. Not "read the manifest" —
"poke it and watch what it tries to do." Safe *because* it's sandboxed.

**M5 — Verdict + evidence** · Correlate static + dynamic findings into a verdict
with evidence. Plain terminal output first.

**M6 — Static pre-check** · Cheap tier before detonation: grep tool
descriptions/manifests for known poisoning/injection patterns (mirrors the
rules-first tier in the ASRT judge).

**M7 — Output formats** · JSON + **SARIF** (GitHub Advanced Security / VSCode /
CI-gatable — kept from the earlier plan, genuinely smart) + Markdown.

**M8 — Package + CI** · pip-installable, GitHub Actions (pytest on every PR),
first open-source release.

---

## Phase 2 (written down so it's not re-derived)

- **eBPF fine-grained monitor** (Rust `aya`) — replaces coarse M3 capture.
- **Rust CLI/TUI shell** (`clap` + `ratatui`) — single-binary distribution,
  polished dashboard; wraps the working Python engine over stdin/stdout JSON.
- **`diff` + `watch` subcommands** — compare two scans / re-scan on update. This
  is where detonate touches the regression thesis: same core, run repeatedly +
  diffed ("did this dependency get worse"). Kept from the earlier plan.
- **Skills input** (SKILL.md + bundled scripts), **repo input** (static-first;
  dynamic only with a clear runnable entry point).
- **Comparison view** ("is there a safer tool in the same category" — the reviewer
  angle nobody else does).
- **Hosted web version** — queue + isolation infra + its own liability model.

---

## Kept from the pasted plan (credit where due)

SARIF output, `diff`/`watch` subcommands, schema-first structs
(ToolDesc/ProbeResult/ScanResult), CI from day one, the clean Rust-shell ⇄
Python-engine stdin/stdout JSON boundary (adopted for phase-2 shell).

## Relationship to the ecosystem

Standalone open-source tool and trust-building front door — same role PromptShield
plays, different surface (agent supply chain). NOT ASRT, NOT SafetyDiff, but shares
the "run it and observe, don't guess" DNA and (in phase-2 watch mode) the
regression thesis. Does not block or depend on anchor_v1 — separate track,
separate repo at publish time.

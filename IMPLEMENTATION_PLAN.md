# detonate — Implementation Plan

**What it is:** an open-source CLI that *detonates* untrusted AI-connected tools
inside a sandbox and reports what they **actually do**, not what their manifest
claims. "Detonation chamber" is the malware-analysis term for exactly this.

**Status:** M0-M2 shipped. Go, single static binary, Docker for the sandbox.

---

## The gap this fills

Every shipping competitor either reads the manifest statically (mcp-scan,
MCPSafe, Cisco) or executes **without** a sandbox and tells the user to isolate
it themselves (Snyk Agent Scan ships `--dangerously-run-mcp-servers`).

**detonate sandboxes by default and probes adversarially.** That is the only
reason it should exist, so it is built first rather than bolted on. A
static-only tier was explicitly considered and rejected: it would make detonate
a sixth entrant in a crowded space, competing on the one axis where it has no
advantage.

---

## What makes a tool dynamic

Worth stating, because "we execute it" is not sufficient — Snyk executes
servers and is still fundamentally a description-reader.

1. **We provide the stimulus.** Adversarial inputs we choose, not just reading
   what is declared.
2. **We observe below the target's control.** Syscalls, egress, files, process
   spawns. A server can lie in a response. It cannot lie about opening a socket.
3. **Evidence is a trace, not an opinion.** "At t=1.2s, after `read_file`, the
   process opened TCP to 34.x.x.x:443 and wrote 4KB."
4. **We catch what static provably cannot:** conditional behavior, runtime-decoded
   payloads, second-stage fetch, rug pulls, declared-vs-actual capability.

Point 4 is the test of whether the tool is really dynamic.

---

## Architecture

```
detonate scan --mcp <cmd> | --skill <path> | --git <url> | --package <spec>
      │
      ▼
┌──────────────────────┐
│  Acquire             │  local path, git clone, or package install
│                      │  package install runs in its OWN container, network ON
└──────────┬───────────┘  ← install-time behavior is itself a finding
           ▼
┌──────────────────────┐
│  Sandbox      (M2 ✔) │  disposable container: network off, read-only rootfs,
│                      │  caps dropped, non-root, memory/PID limits
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Driver       (M1 ✔) │  MCP stdio session / skill loader, INSIDE the sandbox
│                      │  → normalizes to ToolInfo
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Probe + Monitor     │  invoke each tool with adversarial args WHILE watching
│  (the detonation)    │  egress / fs / process. ← what no competitor does
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Verdict + evidence  │  safe / suspicious / dangerous + the trace behind it
└──────────┬───────────┘
           ▼
     JSON / SARIF / Markdown
```

**Verdict model:** `safe` / `suspicious` / `dangerous`, always with evidence,
never a bare score. Deterministic rules over observed facts — an LLM may phrase
the report but must never decide the verdict, or detonate stops being
reproducible and becomes useless in CI.

---

## Input methods

| Input | Example | How it reaches the sandbox | Milestone |
|---|---|---|---|
| Local path | `--skill ./my-skill` | mount read-only | ✔ M2 |
| Git URL | `--git github.com/x/y` | clone on host, mount read-only | M6 |
| Package | `--package "npx some-server"` | two-phase install (below) | M7 |
| Live server | `--url http://...` | no install; manifest only | later |

### The install problem

`npx some-server` needs network to install, but install scripts
(`postinstall`, `setup.py`) are the primary npm/PyPI supply-chain surface.
Installing on the host is unacceptable; installing with network off is
impossible. So: **two containers, two phases.**

```
Phase 1 — ACQUIRE    network ON, no host mounts, disposable
                     observe: what was downloaded, what ran at install time
Phase 2 — DETONATE   network OFF, phase-1 result mounted read-only
                     observe: what it does when invoked
```

Phase 1 is not a necessary evil. Install-time behavior is where second-stage
payloads live and nobody currently watches it.

---

## Testing methodology

MCP servers and skills have different attack surfaces and need different
methodologies. Both share one engine: normalize → probe → observe → verdict.

### MCP servers (execution surface)

| Class | Method |
|---|---|
| Tool poisoning | injection in description, schema, **and returned output** |
| Rug pull | hash manifest, diff against stored baseline across runs |
| Adversarial invocation | path traversal, injected args, oversized input |
| Egress | network on, observe where it connects |
| Install-time | phase 1 above |

Probe taxonomy is built against **MCPTox** (arxiv 2508.14925): 312 scenarios,
14 vulnerability classes. Using a published benchmark makes coverage
*measurable* rather than a matter of our own invention.

### Skills (mostly injection surface)

A skill is largely a big prompt plus scripts, so weight shifts to text:

| Class | Method |
|---|---|
| Instruction injection | SKILL.md **body**, not just frontmatter |
| Permission mismatch | declares `allowed-tools: [Read]`, script spawns a shell |
| Bundled script behavior | run sandboxed, monitor |
| Progressive disclosure | files loaded at runtime beyond the declared set |

---

## Milestones

- [x] **M0** — Scaffold: CLI, target kinds, Docker pre-flight
- [x] **M1** — Drivers: MCP stdio enumeration + skill loader → `ToolInfo`
- [x] **M2** — Sandbox: disposable container, verified confinement
- [ ] **M3** — Sandboxed execution wired into the scan path *(in progress)*
- [ ] **M4** — Behavioral monitor: egress, fs, process spawns
- [ ] **M5** — Adversarial probes, structured on MCPTox's 14 classes
- [ ] **M6** — Verdict + evidence; git URL input
- [ ] **M7** — Two-phase package acquisition
- [ ] **M8** — Rug-pull detection (baseline store)
- [ ] **M9** — JSON / SARIF / Markdown output
- [ ] **M10** — Release: cross-compiled binaries, CI, install docs

### M3 detail (current)

1. Run the MCP server inside the container, stdio crossing the boundary
2. Mount skills read-only, enumerate inside
3. Remove the "sandbox not yet implemented" warning and flip its guard test
4. Orphan reaper on startup for `detonate-*` containers from crashed runs

---

## Deferred, written down so it is not re-derived

- **eBPF fine-grained monitor.** Go's `cilium/ebpf` (what Cilium and Falco
  ship), not Rust. Only once coarse monitoring proves insufficient.
- **Daemonless sandbox.** Linux namespaces + seccomp directly, removing the
  Docker dependency. This is the real fix for the installation problem, which is
  the single biggest adoption risk.
- **`diff` / `watch` subcommands.** Where detonate touches the regression
  thesis: same scan, run repeatedly, diffed.
- **Comparison view** — "is there a safer tool in the same category".
- **Hosted version** — needs a queue, isolation infra, and its own liability
  model.

---

## Non-goals

- Not a static manifest reader; that space is crowded.
- Not a runtime proxy; it tests before and around use, not in the request path.
- Not part of ASRT or SafetyDiff. Separate tool, separate repo. If they ever
  meet, it is over a process boundary and JSON on stdout, never FFI.
- **No LLM in the verdict path.** Report phrasing only, opt-in, and the tool is
  fully functional without it.

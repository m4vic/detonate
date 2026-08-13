# Detonate architecture

Status: describes the code as it exists, 2026-08-05.

This document is **what the code does today**. If something here is wrong, the
document is wrong — fix it.

For the design we are building toward, see
[TARGET_ARCHITECTURE.md](TARGET_ARCHITECTURE.md). For what ships when, see
[ROADMAP.md](ROADMAP.md).

## 1. The job

Detonate takes something an AI agent would install — an MCP server, an Agent
Skill, or a prompt — runs it in a disposable container, calls its tools with
hostile input, and reports what it observed.

One sentence governs the whole design:

> The trace is the product. Verdicts are derived from it and can be recomputed.

Everything downstream of observation is a pure function over recorded events.
That is why no LLM appears anywhere in a verdict, and why two runs of the same
scan produce the same answer.

## 2. The pipeline

```
   detonate <target>
        │
        ▼
   ┌─────────┐   URL?          ┌───────┐
   │  fetch  │────────────────▶│ clone │
   └─────────┘                 └───────┘
        │
        ▼
   ┌─────────┐  is this a skill, an MCP server, or a prompt?
   │ detect  │  (cli/detect.go — decided by looking, not by a flag)
   └─────────┘
        │
        ├──── prompt ──▶ skill.AnalyzePrompt ──────────────┐
        │                                                   │
        ├──── skill ───▶ skill.LoadSkill                    │
        │                skill.Analyze          (static)    │
        │                skill.DetonateScripts  (sandboxed) │
        │                                                   │
        └──── MCP ─────▶ acquire.Install    inert fetch: network ON, scripts off
                         │                  install/build: network OFF, non-root
                         ▼
                         sandbox.Start      network OFF, read-only root,
                         │                  non-root, caps dropped
                         ▼
                         mcpdriver.Session  negotiate, enumerate (paginated)
                         │
                         ▼
                         probe.Run          hostile args, diffed vs a benign
                         │                  baseline call
                         ▼
                         monitor            stderr signatures, docker events
                                                   │
        ┌──────────────────────────────────────────┘
        ▼
   ┌──────────┐
   │  trace   │  ordered []Event — the evidence
   └──────────┘
        │
        ├──▶ baseline.Compare   did the tool descriptions change since last run?
        │
        ▼
   ┌────────────┐
   │ assessment │  risk  +  completeness   (independent, derived, pure)
   └────────────┘
        │
        ▼
   ┌────────┐
   │ report │  text · JSON · SARIF   — same exit code from all three
   └────────┘
```

## 3. Module map

Depth is the Ousterhout measure: how much behaviour hides behind how narrow an
interface. Deep is good.

| Package | Job | Depth |
|---|---|---|
| `sandbox` | Run untrusted code in a disposable container | **Deep** |
| `acquire` | Get a target's dependencies installed and built | **Deep** |
| `mcpdriver` | Speak MCP to a sandboxed server | **Deep** |
| `probe` | Call tools with hostile input and judge the response | **Deep** |
| `skill` | Read, analyze, and detonate an Agent Skill | **Deep** |
| `assessment` | Turn evidence into risk + completeness | **Deep, narrow** |
| `baseline` | Detect rug pulls across runs | Medium |
| `monitor` | Observe a running target | Medium |
| `scan` | Run one target through the whole pipeline | **Deep** |
| `report` | Render a scan as text, JSON, SARIF | Medium |
| `fetch` | Clone a remote target | Shallow, correctly |
| `environment` | Docker pre-flight | Shallow, correctly |
| `mcptest` | A real MCP server for our own tests | Test support |
| `trace` `toolinfo` `toolcall` `target` `scenario` | Shared vocabulary | Thin **on purpose** — see §5 |
| `cli` | Flags, interactive mode, terminal rendering | Wide, but now only a surface |

## 4. The modules in detail

### `sandbox` — the containment boundary

The most important module in the project. Everything else assumes it works.

```go
Start(ctx, name, policy, mounts, command) (*Container, error)
```

Five arguments in, one handle out. Behind that it hides: the entire
`docker run` argument construction, deterministic flag ordering, stdio piping,
a race-safe output buffer, container stop and removal, verification that
removal happened, and orphan reaping for containers a crashed run left behind.

`DefaultPolicy()` is the security contract in one place — network denied,
read-only root, all capabilities dropped, `no-new-privileges`, non-root uid,
memory and PID ceilings, tmpfs for writable paths. A caller cannot accidentally
weaken it by forgetting a flag, because callers do not assemble flags.

**Why it is deep:** a new caller needs to know `Start` and `Close`. It does not
need to know one thing about Docker.

### `acquire` — dependency installation

```go
Detect(dir) Manifest
Install(ctx, targetDir, policy) (*Result, error)
```

Hides ecosystem detection (Node, Python), manifest parsing, entry-point
resolution (`bin`/`main` for Node, `[project.scripts]` for Python), TypeScript
compilation when `dist/` is generated at publish time, monorepo build contexts
where a package inherits config from the repository root, volume lifecycle, and
install-output analysis.

`Install` owns a two-phase boundary. Fetch may use network and uid 0, but npm
lifecycle scripts are disabled, Python accepts wheels only, and VCS/local
dependency forms that can execute source preparation are rejected. A second
network-disabled, non-root container runs install/build hooks. Targets that
cannot satisfy this boundary return `acquisition_unsupported`; the dependency
volume is mounted read-only during detonation.

### `mcpdriver` — the protocol client

```go
OpenSession(...) (*Session, error)
  (*Session) Tools(ctx) ([]toolinfo.ToolInfo, error)
  (*Session) Call(ctx, tool, args) (toolcall.Result, error)
  (*Session) Close() error
```

Four methods. Behind them: JSON-RPC over the container's stdin/stdout,
initialization and capability negotiation, full `tools/list` cursor traversal
with loop detection and page/item ceilings, lossless result normalization
(text, non-text blocks, structured content, `isError`), and diagnosis of *why*
a server died mid-enumeration rather than a bare EOF.

**Why it is deep:** `probe` calls `Call` and gets a `toolcall.Result`. It knows
nothing about JSON-RPC, cursors, or containers.

### `probe` — adversarial invocation

```go
Run(ctx, Caller, tools, timeout) []trace.Event
RunWithResults(...) Result
```

The `Caller` interface is one method, so `probe` does not depend on
`mcpdriver` — it works against anything callable, which is what makes it
testable without Docker.

Hides 13 payloads across 7 MCPTox classes, schema parameter extraction,
argument construction, and the judgement in `checkResponse`. The important
piece is **baseline diffing**: every hostile call is compared against a benign
one, so a tool that always echoes its input is not reported as leaking. That
single decision is why the false-positive rate came down.

Also classifies failures rather than swallowing them: `isNetworkBlocked`
distinguishes "the sandbox worked" from "the tool is broken", so an
egress-dependent tool becomes an `unsupported` scenario rather than a finding.

### `skill` — Agent Skills

```go
LoadSkill(dir) (Skill, error)
Analyze(Skill) []trace.Event            // static: it is a large prompt
AnalyzePrompt(text) []trace.Event       // same rules, any text
DetonateScripts(ctx, dir, sk, policy) []trace.Event   // dynamic
FindBundledScripts(dir) ([]string, error)
```

A skill is mostly text an agent obeys, so most of the danger is static. But
bundled scripts are real programs, so they run in the sandbox one at a time.

`FindBundledScripts` recurses. It did not, once, and Anthropic's own `docx`
skill — 15 Python files under `scripts/` — was reported as "0 bundled scripts,
instructions only". A clean verdict on the reference implementation of the
format. That is why recursion is a documented requirement and not an
optimization.

`checkPermissions` implements the declared-versus-actual check: a skill
declaring `allowed-tools: [Read]` that instructs shell commands is a
permission mismatch. Generalizing this into a full capability model is
[ROADMAP.md](ROADMAP.md) v0.5.0.

### `assessment` — the verdict

```go
Summarize(events, scenarios) Summary
Validate(scenarios) error
```

A pure function. No I/O, no clock, no network. Given the same events it returns
the same summary, forever — which is the entire reason a detonate exit code can
gate a CI pipeline.

It computes **two independent values**:

- **Risk** — what the evidence shows.
- **Completeness** — how much of the modeled surface was actually reached.

They are separate because collapsing them is the failure that makes security
tools harmful. "Nothing is wrong" and "almost nothing was tested" must never
render identically. `Validate` enforces that every requested scenario reached a
terminal outcome, so a phase cannot vanish silently.

### `baseline`, `monitor`, `report`

**`baseline`** stores a hash of tool descriptions per target and diffs the next
run against it, catching rug pulls where a server ships benign descriptions and
swaps them later. Identity is derived from what the user asked for plus
`--path`, because two packages in one repository are two targets. Baselines
currently auto-advance; explicit approval is v0.8.0.

**`monitor`** observes a running target two ways: `Analyze` matches typed
signatures against container stderr, and `WatchContainer` streams Docker
lifecycle events. Docker events are **collected but not yet wired into
verdicts** — an honest gap, since stderr is target-controlled and therefore
weak evidence.

**`report`** renders one `Scan` three ways. `Build` is the single place a trace
becomes a report, so text, JSON, and SARIF cannot disagree. SARIF
`fingerprint` must stay stable across runs or GitHub treats every finding as
new — which is why canary nonces are barred from it ([ROADMAP.md](ROADMAP.md)
v0.2.0).

## 5. The vocabulary layer

`trace`, `toolinfo`, `toolcall`, `target`, and `scenario` are thin, and that is
correct. **Do not "fix" them by adding behaviour.**

They exist so that deep modules can talk to each other without importing each
other. `probe` produces `trace.Event`; `assessment` consumes `trace.Event`;
neither imports the other. `skill` and `mcpdriver` both normalize into
`toolinfo.ToolInfo`, which is why one probe engine works against two entirely
different target kinds.

Shallowness is a defect when a module *wraps* something. It is a virtue when a
package *is* a shared type. These are the second kind.

`trace` is the most important of them: read its package comment before changing
anything about evidence.

## 6. `scan` — the pipeline, and why it is its own package

```go
Run(ctx, Request, Progress) (*Report, error)
```

`scan` acquires dependencies, launches the target in the sandbox, enumerates
what it exposes, and probes it. It does no printing, reads no flags, and picks
no exit code.

The pipeline used to live inside `cli`, and the internal callers did not call
it directly — they built a command line and handed it back to the flag parser:

```go
// what runMCP used to do
args := []string{"--mcp", d.Command, "--dir", d.Dir}
if install { args = append(args, "--install") }
return a.scan(ctx, args)
```

Every option crossed that boundary as a string the compiler could not check,
and nothing but a terminal could start a scan.

Two design points worth keeping:

**`Stages` is named for what runs, not what is skipped.** A zero value means
the least execution, so a caller that forgets a field gets a safer scan rather
than a more dangerous one. For a package whose job is running untrusted code,
the default has to fail toward doing less.

**`Progress` is a callback, not a writer.** A scan spends minutes doing things
the user should be told about, but the pipeline does not know whether a
terminal, a log, or nothing is listening. The caller decides.

`cli` is now a surface: parse flags → build a `Request` → call `scan.Run` →
render. Everything that scans arrives at one typed entry point, `execute()`.

### What remains in `cli`

Fetching and detection stayed, deliberately. They are how a *person* names a
target — resolving a URL, guessing whether a folder is a skill — and they are
well covered by tests where they are. `scan` deals in targets that have already
been named.

The engine modules are in good shape and should be left alone.

## 7. Conventions

**Comments explain why, not what.** The existing standard is high — see
`trace/event.go`, or `baselineIdentity` in `cli/run.go`, which explains that
without folding `--path` into the identity, two packages in one repository
share a baseline and invent rug-pull findings about each other. That is a
comment worth having. `// increment i` is not. Match the former.

**Every package has a doc comment saying why it exists.** All of them do
today. Keep it that way.

**Prefer a deeper module over a new one.** If a change fits behind an existing
narrow interface, put it there.

**Tests pair with their file.** `foo.go` → `foo_test.go`. Docker-dependent
tests live in the package they exercise and are expected to actually start
containers.

### Adding things

- **A new probe payload** → `probe/payloads.go`, plus positive and negative
  fixtures. Nothing else changes.
- **A new ecosystem** (Go, Ruby) → `acquire/detect.go` for the manifest and
  entry point, `acquire/install.go` for the install command, a pinned image in
  `sandbox/image.go`.
- **A new output format** → `report`, consuming the same `Scan` that JSON and
  SARIF consume. Never re-derive findings from the trace in a renderer.
- **A new evidence source** → emit `trace.Event` with an accurate `Source`.
  Evidence that cannot name its own origin is not evidence.
- **A new pipeline stage** (canaries, budgets) → `scan`, announced through
  `Progress`. It should not require a new flag to reach.

## 8. Invariants

These hold at every version. They are restated in
[ROADMAP.md](ROADMAP.md) §Invariants because they outrank any feature.

1. No LLM in any verdict.
2. Risk and completeness stay independent.
3. Target-controlled code never executes on the host.
4. The detonation sandbox never gains network access. Observability is added by
   instrumenting the inside, never by loosening the boundary.
5. No telemetry.
6. Every finding carries evidence.

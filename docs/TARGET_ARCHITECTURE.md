# Detonate target architecture

Status: proposed target architecture, grounded in the code at commit `73da967`
and live tests run on 2026-07-30.

This document deliberately separates:

- **Current**: behavior verified in the repository today.
- **Target**: the architecture Detonate should implement.
- **Experimental**: behavior that depends on an unstable protocol, model, or
  sandbox backend and must not be advertised as generally supported.

The implementation order and acceptance gates are in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). Verified interoperability
results are in [COMPATIBILITY.md](COMPATIBILITY.md).

## 1. Product definition

Detonate is a local-first security and compatibility test harness for:

1. MCP servers, including their tools, resources, prompts, protocol behavior,
   transports, authorization boundary, and optional extensions.
2. Agent Skills, including `SKILL.md`, referenced assets, bundled programs,
   dependency installation, and realistic invocation flows.
3. Raw prompts and prompt templates.
4. Optional end-to-end agent runs in which a real LLM selects and calls the
   target.

It combines three complementary modes:

| Mode | Purpose | Determinism | May affect the risk verdict? |
|---|---|---:|---:|
| Static | Inspect manifests, source, dependencies, schemas, prompts, and skill files without executing target code | High | Yes |
| Sandboxed dynamic | Execute protocol and behavior scenarios inside an isolated environment | High when fixtures are fixed | Yes |
| Agentic / LLM | Measure whether a model selects, trusts, or is manipulated by the target | Statistical | Evidence only by default |

Static and dynamic testing answer different questions. Static checks can prove
that a dangerous instruction or dependency is present. Dynamic checks can prove
that an action occurred. Agentic testing measures whether the action is likely
to be reached by a particular host/model configuration.

## 2. Guarantees and non-goals

### 2.1 Required guarantees

1. **No silent host execution.** Target-controlled code must execute only in a
   selected sandbox backend. If the backend is unavailable, the dynamic stage
   fails closed.
2. **No false clean.** A skipped, invalid, timed-out, crashed, or unsupported
   scenario reduces completeness. It can never be presented as a successful
   security test.
3. **Verified teardown.** A scan cannot complete while its target container,
   child processes, temporary credentials, network namespace, or volumes may
   still be live.
4. **Evidence before opinion.** Every finding identifies the scenario, target
   component, source, timestamp, and bounded evidence that produced it.
5. **Reproducibility.** A report identifies an immutable target where possible
   or a timestamped remote observation otherwise, plus dependency, image,
   rule-pack, probe-pack, protocol, platform, and configuration versions.
6. **Secrets stay outside the target by default.** Model-provider credentials
   and default personal/cloud credentials must never be injected into untrusted
   target code. A remote-auth compatibility scenario may send only an explicit,
   scoped, disposable target credential to that target endpoint; dynamic
   security tests otherwise use synthetic canaries and service emulators.
7. **Resource bounds everywhere.** Input size, output size, tool count, schema
   depth, recursion, concurrency, memory, PIDs, CPU, disk, network, and wall
   time all have explicit budgets.

### 2.2 Honest non-goals

- A `no_findings` result is not proof that a target is safe.
- Docker alone is not a hardened VM boundary on native Linux.
- An LLM is not an authority for deterministic security verdicts.
- Detonate is not a production MCP proxy and does not approve live actions on
  behalf of a user.
- Detonate does not silently send proprietary source, prompts, or traces to a
  hosted model.

## 3. Current implementation and target delta

| Capability | Current | Target |
|---|---|---|
| Local MCP | Legacy-generation stdio, tools only | Dual-era stdio plus full primitive and extension inventory |
| Remote MCP | Not supported | Streamable HTTP, optional deprecated SSE compatibility, OAuth and header-based auth |
| MCP inventory | `tools/list` | Versions, capabilities, tools, resources, templates, prompts, subscriptions, extensions |
| Dynamic inputs | 13 payloads against top-level string fields | Schema-valid scenario generation for nested and mixed types |
| Behavioral observation | Target-controlled stderr patterns | Runtime events, bounded logs, filesystem diff, process events, controlled egress, optional eBPF |
| Agent Skills | Regex analysis plus scripts run without arguments | Full artifact graph, dependency-aware scenarios, realistic invocations, optional LLM host |
| Prompts | Regex signatures | Static normalization plus repeatable multi-model attack/defense suites |
| Acquisition | Script-disabled/wheel-only fetch, then offline non-root install/build | Immutable allowlisted resolve/fetch with provenance, offline build, offline/controlled detonation |
| Results | Risk only (`clean`/`suspicious`/`dangerous`) | Risk, completeness, coverage, confidence, and failure reason |
| Reproducibility | Partial | Immutable provenance envelope and record/replay |
| Distribution | Workflow exists but entrypoint is untracked | Signed release artifacts, SBOM, package-manager installs, clean-checkout gate |

The current monitor must not be described as syscall, filesystem, process, or
complete egress monitoring. The normal scan path analyzes stderr. A Docker event
watcher exists but is not wired into sessions.

## 4. Protocol baseline

The latest MCP specification at the time of this design is
[`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28).
It is a major compatibility boundary:

- Modern requests carry protocol version and client capabilities in per-request
  `_meta`; client identity is recommended rather than mandatory.
- Servers implement `server/discover` in place of legacy initialization for
  discovery. A client may call it or send another request directly and handle
  version negotiation errors; it is not a mandatory preflight handshake.
- Streamable HTTP is stateless and sessionless for this revision.
- Multi-round-trip results replace server-initiated roots, sampling, and
  elicitation requests. Request-scoped progress/log notifications remain, and
  list/resource changes move to `subscriptions/listen`.
- Roots, sampling, logging, dynamic client registration, and legacy HTTP+SSE
  are deprecated for new designs but remain compatibility cases for older
  negotiated revisions.
- Extensions are negotiated explicitly. Tasks and MCP Apps are defined
  extensions; Skills over MCP is still working-group/SEP work and must remain
  experimental.

Detonate currently uses `github.com/modelcontextprotocol/go-sdk v1.5.0`, which
targets the older protocol generation. The stable Go SDK `v1.7.0`, released on
2026-07-28, adds `2026-07-28` support while preserving negotiation with older
revisions. Detonate still needs an era/version abstraction before upgrading so
legacy lifecycle behavior cannot leak into modern request handling.

### 4.1 Compatibility rule

Protocol support is a matrix, not a boolean:

```text
protocol revision × transport × primitive × extension × auth mode
```

Every report records the negotiated revision. A capability is only marked
tested when its scenario suite ran successfully for that revision and
transport.

## 5. Result model

Risk and execution completeness are independent.

### 5.1 Risk

| Value | Meaning |
|---|---|
| `not_assessed` | No trustworthy risk assessment was possible; inspect completeness and phase errors. |
| `no_findings` | No enabled rule produced a finding. This does not imply safety. |
| `suspicious` | Review-worthy behavior or a medium-confidence policy violation was observed. |
| `dangerous` | High-confidence harmful behavior, policy violation, or proven exploit effect was observed. |

Human output may render `no_findings` as “no findings,” not “safe.”

### 5.2 Completeness

| Value | Meaning |
|---|---|
| `complete` | Every required scenario for the selected profile ran and produced a valid result. |
| `partial` | At least one scenario passed, but one or more were skipped or unsupported. |
| `inconclusive` | The target ran, but environmental or target behavior prevented meaningful coverage. |
| `failed` | Detonate could not safely acquire, start, communicate with, or tear down the target. |

A compact final state is the pair, for example:

```text
risk=no_findings, completeness=partial
```

### 5.3 Scenario outcomes

Every scenario ends in exactly one of:

```text
pass | finding | skipped | unsupported | timeout | target_error |
harness_error | teardown_error
```

Coverage is computed from scenario outcomes, not from the number of log lines.
Reports expose both counts and stable scenario IDs.

## 6. Trust boundaries

```text
┌──────────────────────────── trusted host process ────────────────────────────┐
│ CLI/config ─ resolver ─ planner ─ assessor ─ reporter                       │
│       │          │          │          ▲          ▲                         │
│       │          │          │          │ evidence │                         │
│       │          │          ▼          │          │                         │
│       │      immutable artifact store  │    optional LLM adapter            │
│       │          │                     │    (real provider key stays here)  │
└───────┼──────────┼─────────────────────┼──────────────┬──────────────────────┘
        │          │                     │              │
        ▼          ▼                     ▼              ▼
┌──────────────── fetch sandbox ───────────────┐  provider endpoint
│ network on; target code disabled             │  or local Ollama
│ downloads only; hashes and provenance output │
└──────────────────────┬───────────────────────┘
                       ▼
┌──────────────── build sandbox ───────────────┐
│ network off; target build/hooks may execute  │
│ non-root; bounded; full evidence collection  │
└──────────────────────┬───────────────────────┘
                       ▼
┌──────────── detonation sandbox/network ──────┐
│ target server or skill script                │
│ read-only artifact; synthetic data/secrets   │
│ no egress or only explicit service emulators │
└──────────────────────────────────────────────┘
```

The Docker daemon is privileged infrastructure and belongs outside the trusted
application boundary. Detonate must never mount its socket into a target
container. On native Linux, rootless Docker or an isolation backend with a
separate kernel is preferred.

## 7. Scan state machine

```text
resolve → snapshot → static → plan → fetch → build → start → discover
   → begin collection → execute scenarios → teardown while collecting
   → finalize evidence → assess → report
```

Each transition writes a journal entry. On cancellation or failure, control
jumps to `teardown` using a fresh bounded cleanup context, then finalizes
collectors, assesses, and reports. Evidence must survive a partial run, and
kill/destroy/removal events must be captured before collection ends.

Retry is allowed only for idempotent infrastructure operations such as an image
pull or registry fetch. Tool calls, skill scripts, auth flows, and external
actions are never retried unless the scenario explicitly declares them safe.

## 8. Component architecture

The target Go package layout is:

```text
api.go                     public Go API: ScanRequest, ScanResult, Scanner
cmd/detonate/              thin executable entrypoint
internal/app/              orchestration and dependency wiring
internal/config/           versioned config, profiles, validation
internal/target/           normalized TargetSpec and recorded identity/snapshot
internal/resolve/          local, git, package, registry, URL resolution
internal/static/           artifact graph and versioned rule packs
internal/acquire/          fetch/build plans and provenance
internal/protocol/
  mcp/                     version-neutral MCP inventory and scenarios
  skill/                   Agent Skill and Skills-over-MCP adapters
  prompt/                  raw prompt adapter
internal/transport/
  stdio/                   sandboxed process transport
  streamhttp/              Streamable HTTP transport
  sselegacy/               optional compatibility adapter
internal/scenario/         definitions, generation, scheduling, outcomes
internal/sandbox/          backend-neutral policy and lifecycle
internal/sandbox/docker/   default backend
internal/observe/          log, runtime, fs, process, and network collectors
internal/llm/              optional provider-neutral agent loop
internal/evidence/         bounded events and provenance
internal/assess/           deterministic rules and result aggregation
internal/baseline/         versioned inventory/behavior comparison
internal/report/           text, JSON, SARIF, JUnit, evidence bundle
```

Migration should be incremental. Existing packages remain usable while
interfaces are introduced around them.

The root `detonate` package has no terminal output and no global mutable run
state. Each `Scanner.Scan` call owns its configuration, buffers, deadlines, and
dependencies so CLI, tests, embedded Go users, and future concurrent service
runs share one implementation safely.

### 8.1 Core interfaces

Conceptually, the orchestration boundary is:

```go
type Adapter interface {
    Resolve(context.Context, TargetSpec) (ResolvedTarget, error)
    Inventory(context.Context, Runtime) (Inventory, []ScenarioResult, error)
    Scenarios(Inventory, Profile) []Scenario
    Execute(context.Context, Runtime, Scenario) ScenarioResult
}

type Sandbox interface {
    Start(context.Context, SandboxPlan) (Runtime, error)
    BeginCollect(context.Context, Runtime) (Collector, error)
    Close(context.Context, Runtime) TeardownResult
    Finalize(context.Context, Collector, TeardownResult) (EvidenceBundle, error)
}
```

Concrete SDK types must not leak into inventory, scenarios, evidence, or
reports. The orchestrator owns budgets, a fresh bounded teardown context, and
evidence finalization after teardown. This keeps protocol upgrades and transport
additions isolated.

## 9. Resolution and recorded identity

Supported target forms should become explicit:

| Target | Example | Recorded identity or observation |
|---|---|---|
| Local artifact | `detonate scan ./server` | Merkle/hash snapshot, not live path |
| Git | `detonate scan github.com/org/repo@<sha>` | Full commit SHA plus subpath |
| Registry server | `detonate scan registry:name@version` | Registry record and package/remotes digest |
| Package | `detonate scan npm:@scope/server@1.2.3` | Registry, exact version, integrity hash |
| Remote MCP | `detonate scan https://host/mcp` | Observed endpoint snapshot: timestamp, URL, negotiated protocol, server identity, and inventory/metadata hashes |
| Skill | `detonate scan ./skill` | Artifact tree hash |
| Prompt | `detonate scan ./prompt.md` | Content hash |

Mutable Git branches and floating package/image tags may be accepted for
convenience, but are resolved once and the immutable value is recorded before
analysis begins.

A live remote endpoint is not immutable unless it supplies an attested deploy
digest. Reports must label remote observations as time-bound and
non-reproducible; record/replay preserves evidence but does not prove the
service has not changed.

The resolver must enforce path containment after symlink resolution, reject
device files and unsafe archives, cap file count/size/depth, and record anything
it skipped.

## 10. Static analysis

Static analysis always runs before target code.

### 10.1 Common checks

- Artifact inventory, content hashes, executable bits, symlinks, and hidden
  files.
- Secrets and private-key material, with redacted evidence.
- Obfuscated/encoded content, Unicode control characters, bidirectional text,
  and mixed-script identifiers.
- Dependency manifests, lockfiles, registry integrity, provenance, known
  vulnerabilities, lifecycle/build hooks, and unpinned dependencies.
- Suspicious URLs, commands, process creation, credential paths, and
  environment access.
- Versioned suppressions with reason, owner, and expiry.

### 10.2 MCP checks

- Server metadata, package command, environment requirements, and transport.
- Tool/resource/prompt names, descriptions, annotations, schemas, MIME types,
  and `_meta` fields.
- Description/output injection patterns and declared-versus-observed drift.
- Dangerous schema defaults, ambiguous or over-broad tools, header annotations,
  and auth metadata.
- Protocol-version and extension claims.

### 10.3 Skill and prompt checks

- Parse the complete skill tree, not only `SKILL.md`.
- Resolve referenced files and flag paths that escape the skill root.
- Separate explanatory mentions from executable instructions.
- Compare declared tools/permissions with instructions, scripts, and assets.
- Track progressive-disclosure paths.
- Normalize prompt templates before signature matching while retaining original
  byte offsets for evidence.

Rules have stable IDs, severity, confidence, supported artifact kinds, tests,
and a rule-pack version. A regex match without semantic context should normally
be an observation, not a critical finding.

## 11. Safe acquisition and build

The current implementation has a real safety split: networked npm fetch runs
with lifecycle scripts disabled, Python fetch is wheel-only, and all
target-controlled install/build hooks run offline and non-root. Unsupported
source/VCS/local forms are rejected explicitly. The target architecture keeps
those phases while adding allowlisting, content-addressing, provenance, and
complete resource/evidence controls.

### 11.1 Resolve/fetch

- Network enabled through an allowlisted proxy.
- No target code, lifecycle scripts, native build, or package import.
- npm uses lockfiles and `--ignore-scripts`.
- Python prefers wheels; source distributions are downloaded as data and built
  later offline.
- Go uses a pinned toolchain and module checksums.
- Downloads are content-addressed and an SBOM/provenance record is emitted.

If a package manager cannot guarantee a no-execution fetch, that ecosystem uses
a registry-specific downloader or the phase is explicitly marked
`inconclusive`.

### 11.2 Offline build

- Network disabled.
- Target-controlled build and lifecycle code may execute.
- Non-root user; pre-owned output volume; read-only source snapshot.
- Hard CPU, memory, PID, disk, output, and time limits.
- Runtime, process, filesystem, and attempted-network evidence collected.
- A build that demands network fails as a compatibility result; Detonate does
  not silently weaken the policy.

### 11.3 Detonation

- Built artifact and dependencies mounted read-only.
- Fresh writable tmpfs/home/work directory per scenario.
- Network `none` by default, or a scenario-specific isolated service network.
- Synthetic credentials and canary data only.
- No provider API key, Docker socket, host home, SSH agent, cloud metadata, or
  unrelated repository directory is mounted.

## 12. Sandbox policy and backends

The default Docker profile should include:

- Read-only rootfs and target/dependency mounts.
- Non-root user and user namespaces/rootless daemon when possible.
- All capabilities dropped, `no-new-privileges`, default or stricter seccomp,
  and no devices or Docker socket.
- `--network none` or a dedicated internal test network.
- Hard CPU quota, memory plus swap ceiling, PID ceiling, ulimits, tmpfs/disk
  quotas, and wall-clock deadline.
- Pinned image digests with recorded runtime/toolchain versions.
- Unique labels/names and daemon-side teardown verification.

Backend profiles:

| Backend | Use | Status |
|---|---|---|
| Docker | Default compatibility path on Windows, macOS, and Linux | Current base |
| Rootless Docker/Podman | Reduced daemon privilege on Linux | Planned |
| gVisor | Stronger syscall boundary with container workflow | Planned |
| Kata Containers | VM-backed OCI isolation | Planned |
| Firecracker worker | Highest-risk hosted/batch scans | Future |

The report must state which boundary was actually used.

## 13. Observation architecture

Evidence collectors are independent and declare their coverage:

1. **Protocol transcript**: bounded, redacted JSON-RPC metadata and content
   hashes; full sensitive content only in an opt-in encrypted bundle.
2. **Runtime lifecycle**: Docker/container events, exit status, OOM, deadline,
   signal, restart, and verified removal.
3. **Logs**: bounded ring buffers for stdout/stderr, truncation markers, binary
   detection, and total byte counts.
4. **Filesystem**: before/after snapshots of writable mounts, file metadata,
   hashes, and canary access.
5. **Process**: command, parent/child relationships, exit codes, and resource
   usage from the runtime; optional syscall detail.
6. **Network**: DNS and TCP attempts through an isolated gateway; HTTP capture
   and response fixtures where applicable. TLS payloads are not claimed visible
   unless the scenario deliberately trusts a test CA.
7. **Optional Linux sensor**: eBPF/Fanotify for fine-grained process, file, and
   network events.

Collector failure reduces completeness and is never swallowed.

## 14. MCP adapter

### 14.1 Transports and authorization

- `stdio`: the server process runs in the sandbox; protocol crosses owned
  pipes.
- `streamable-http`: connect to a remote endpoint or start a local server in an
  isolated network and connect through a gateway.
- `sselegacy`: optional compatibility only; marked deprecated.
- `auth`: bearer/header profiles, OAuth discovery/PKCE, client credentials, and
  enterprise-managed authorization are exercised with a local fake issuer
  whenever possible.

Auth secrets are references resolved by the trusted host. They are never
written into reports. Remote live tests default to read-only discovery and
require explicit consent for tool calls.

### 14.2 Inventory

For each negotiated protocol revision, inventory:

- Server identity, supported versions, capabilities, and extensions.
- Tools, including input/output schemas, annotations, and metadata.
- Tool results across text, image, audio, embedded resource, and structured
  content; `isError` is a target/tool outcome, not a transport failure.
- Resources and resource templates, MIME types, pagination, and subscriptions.
- Prompts, arguments, returned messages, and embedded resources.
- Supported client interactions such as roots, elicitation, and legacy
  sampling, or their modern multi-round-trip equivalents.
- Tasks, MCP Apps, and other negotiated extensions as separate modules.

### 14.3 Protocol scenarios

Integrate the official
[`modelcontextprotocol/conformance`](https://github.com/modelcontextprotocol/conformance)
executable test framework for the scenarios it implements. The specification
and schema remain normative. Add Detonate-specific robustness cases:

- A first-party Go fault-injection server provides pinned legacy and
  `2026-07-28` modes over stdio and stateless Streamable HTTP. It is the
  deterministic oracle for crashes, delays, pagination, malformed metadata,
  MRTR, subscriptions, oversized results, and controlled side effects.

- Malformed JSON-RPC, wrong IDs, duplicate IDs, invalid result/error shapes.
- Protocol errors versus successful `tools/call` results carrying
  `isError=true`, including mixed and structured content.
- Version mismatch, downgrade/fallback, capability violations, and invalid
  extension negotiation.
- Pagination loops, duplicate cursors, notification floods, oversized schemas,
  deep nesting, binary content, and invalid UTF-8.
- Cancellation, timeout, slowloris, crash, restart, and shutdown behavior.
- stdout protocol corruption for stdio.
- Origin/DNS-rebinding checks, header mismatch/injection, redirects, auth token
  scope, and session fixation/hijacking for HTTP generations that use sessions.

## 15. Scenario generation and scheduling

A versioned scenario definition contains:

```text
id, target kind, prerequisites, setup, input generator, oracle,
side-effect class, isolation mode, timeout, cleanup, and expected coverage
```

The generator builds schema-valid inputs first:

- Required properties of every JSON type.
- Nested objects/arrays, enums, formats, bounds, defaults, unions, and
  `additionalProperties`.
- Pairwise mutation so one hostile field is changed while other required fields
  remain valid.
- Benign controls and leak canaries.
- User fixtures for domain-specific types.

Each mutating scenario gets a fresh state snapshot or declares a reversible
cleanup. Destructive remote calls are disabled unless the user explicitly
selects a disposable test account and profile.

The scheduler enforces global and per-target budgets, limits concurrency, stops
dependent scenarios after a server death, and records one root crash rather
than a cascade of duplicate findings.

## 16. Agent Skills and prompts

Agent Skills and Skills over MCP are related but distinct:

- A filesystem Agent Skill is a directory artifact with `SKILL.md`, scripts,
  references, and assets.
- Filesystem skills are validated against the published Agent Skills
  specification (and `skills-ref` compatibility) before Detonate-specific
  security rules run.
- Skills over MCP is evolving extension work. Support must be feature-flagged
  and versioned until the SEP and SDK support stabilize.
- MCP prompts are a core server primitive and belong in MCP inventory/testing,
  not in the filesystem-skill loader.
- A raw prompt is inert text until a host/model uses it.

### 16.1 Realistic skill execution

Do not run every script with no arguments and call that coverage. A skill
scenario supplies:

- Working directory, command, arguments, stdin, environment, and fixture files.
- Dependency/build plan and the correct runtime image.
- Expected exit status/output contract.
- Synthetic secrets and services.
- Files the agent is expected and forbidden to read.

Scenarios may be inferred conservatively from explicit command examples, but
unresolved invocations are `skipped`/`inconclusive`, not clean.

Malformed frontmatter, an escaped reference, or a scan/file limit is a visible
validation or completeness result. Helper libraries are not treated as direct
entrypoints unless a scenario declares them executable.

### 16.2 Progressive disclosure

The harness records which skill files, references, and assets were exposed to
the agent at each step. It tests whether hidden or late-loaded content changes
tool selection, requests secrets, or overrides higher-priority instructions.

Experimental Skills over MCP support is isolated behind an extension flag and
tests `skills/list`, `skills/get`, and backing `resources/read` behavior. It
verifies per-file digests, uses per-origin namespaces, bounds pagination and
resource size, rejects cross-origin/path escape and content rotation, and never
turns a fetched skill into execution authority or a permission grant.

## 17. Optional LLM/agentic mode

The deterministic engine remains fully usable without a model. Agentic mode is
an opt-in experiment runner that asks:

- Does the model choose the poisoned tool/skill?
- Does tool output override system/user instructions?
- Does the model attempt to reveal a synthetic secret?
- Does the model respect approval boundaries and tool schemas?
- Are results stable across repeated trials and providers?

### 17.1 Provider interface

```go
type Provider interface {
    Complete(context.Context, Request) (Response, error)
    Capabilities(context.Context) ProviderCapabilities
}
```

Adapters:

- Ollama native `/api/chat`, plus its OpenAI-compatible endpoint where useful.
- OpenAI Responses API.
- Anthropic Messages API.
- Gemini Interactions API (or `generateContent` compatibility).
- Record/replay provider for CI.

Use Go's standard HTTP stack and small provider adapters before adding large
vendor SDK dependencies.

### 17.2 Safety and reproducibility

- Provider keys stay in the trusted orchestrator and are redacted at source.
- Model-provider traffic uses a trusted control-plane client/gateway; the
  untrusted target sandbox cannot reach that network or read provider
  credentials.
- Only synthetic secrets are offered to targets/models.
- Hosted-provider upload requires explicit consent and a preview of data classes
  leaving the machine.
- Record provider, model identifier, capability snapshot, request ID, prompt and
  tool-schema hashes, sampling settings, token use, latency, and cost.
- Run repeated trials. Report rates and confidence intervals, not a single
  binary conclusion.
- Temperature zero and seeds are used when available but are not treated as
  deterministic guarantees.
- Model judgments may summarize evidence; they do not create or suppress
  deterministic findings.

Ollama is the recommended first adapter because it is local and already exposes
structured tool calls. Hosted adapters follow after record/replay and redaction
are complete.

## 18. Evidence and provenance

Every JSON report has a versioned envelope:

```text
scan ID and timestamps
Detonate version/commit and report schema
target locator, immutable identity or timestamped remote snapshot, artifact hash, and subpath
dependency lock/integrity and SBOM hash
sandbox backend, image digest, runtime versions, and policy hash
MCP protocol/transport/capabilities
rule/probe/scenario pack versions
configuration and suppression hashes
scenario results and collector coverage
findings, observations, bounded evidence, and redaction/truncation markers
teardown result
optional LLM provider/model/prompt/tool-call metadata
```

Evidence is append-only during a run. Large/full transcripts go in a separate
content-addressed bundle with retention controls; normal reports contain
bounded excerpts and hashes.

## 19. Baselines and change detection

The baseline includes more than descriptions:

- Artifact, dependency, and build hashes.
- Protocol versions, capabilities, extensions, and transport/auth metadata.
- Tool names, descriptions, annotations, input/output schemas.
- Prompts, resources/templates, and MIME/content hashes.
- Static findings and scenario coverage.
- Observed destinations, files, processes, and side-effect classes.

Baseline format is versioned and supports migration. A change produces a diff,
not automatically a critical finding. Risk depends on what changed and whether
the new behavior was authorized.

A scan creates an immutable baseline candidate; it never silently overwrites an
approved baseline. Promotion is an explicit `baseline approve` operation with
actor/reason metadata. Incomplete or finding-bearing candidates require an
auditable override. Stores use atomic writes, locking, append-only history, and
an export/import path for ephemeral CI runners.

## 20. Configuration and profiles

Use a versioned `detonate.yaml` plus CLI overrides:

```yaml
schema: detonate.config/v1
profile: standard
target:
  ref: github.com/example/server@<sha>
sandbox:
  backend: docker
network:
  mode: none
coverage:
  require: standard
llm:
  enabled: false
```

Profiles:

- `quick`: immutable resolution, static checks, and protocol inventory.
- `standard`: offline build, inventory, safe dynamic scenarios, no live egress.
- `deep`: expanded generators, filesystem/network emulators, and compatibility
  cases.
- `agentic`: standard/deep plus selected LLM matrix.
- `hostile`: strongest available isolation backend and extended monitor.

Configuration validation happens before acquisition. Unknown fields are errors
unless a compatible extension owns them.

## 21. Failure handling and teardown

- A root context owns the scan; child budgets cannot exceed it.
- Teardown uses a fresh bounded cleanup context when the root scan context is
  cancelled; collectors remain active until destroy/removal verification ends.
- Output readers cannot block target shutdown.
- Buffers are bounded ring buffers with byte/drop metrics.
- On target death, dependent scenarios stop and one causal event is emitted.
- Session close, stdin close, graceful stop, force stop, removal, volume/network
  cleanup, and final existence checks form one idempotent teardown transaction.
- Orphan reaping uses scan labels plus age and never removes unrelated
  containers.
- A teardown error forces `completeness=failed` and a non-zero exit.

## 22. Reporting and CI

Formats:

- Text for humans.
- Versioned JSON as the canonical machine format.
- SARIF for code scanning, with deterministic rule/result ordering.
- JUnit for compatibility/scenario suites.
- Optional HTML/evidence bundle for interactive review.

Exit behavior should remain scriptable:

| Exit | Meaning |
|---:|---|
| 0 | Required coverage complete and no findings above the configured gate |
| 1 | Harness/runtime/teardown failure |
| 2 | Invalid usage or environment |
| 3 | Finding threshold reached |
| 4 | Coverage incomplete or inconclusive and configured to gate |

Changing the current exit contract requires a report-schema/CLI version note and
a compatibility period.

## 23. Distribution and supply-chain security

Release prerequisites:

- Entrypoint and all release inputs tracked in Git.
- Clean-checkout build/test on every pull request.
- Cross-platform binaries with version metadata.
- Reproducible build settings, checksums, signatures, provenance, and SBOM.
- Pinned GitHub Actions and container image digests.
- Homebrew, Scoop/winget, and `go install` paths tested from clean machines.
- `detonate doctor` validates Docker/backend, architecture, disk, networking,
  and required images with actionable remediation.

Docker remains the default dynamic prerequisite. Prompt-only/static-only use
must work without it, and the CLI must say exactly which requested stages were
skipped.

## 24. Architecture decision records

Create ADRs for decisions whose trade-offs should not be repeatedly reopened:

1. Risk and completeness are orthogonal.
2. Three-phase acquisition with offline target-code execution.
3. Provider-neutral LLM boundary and no model in deterministic verdicts.
4. Dual-era MCP protocol/transport abstraction.
5. Docker default plus stronger optional backends.
6. Content-addressed evidence and immutable local/artifact identity with
   timestamped remote snapshots.
7. Specification/schema as normative authority; official conformance as the
   executable regression framework for implemented scenarios.

## 25. Primary references

- [MCP specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP versioning and compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [MCP stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
- [MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [Official MCP conformance framework](https://github.com/modelcontextprotocol/conformance)
- [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
- [Official MCP Registry](https://registry.modelcontextprotocol.io/)
- [MCP Go SDK releases](https://github.com/modelcontextprotocol/go-sdk/releases)
- [Agent Skills specification](https://agentskills.io/specification)
- [Skills over MCP working group](https://modelcontextprotocol.io/community/working-groups/skills-over-mcp)
- [Experimental Skills over MCP threat model](https://github.com/modelcontextprotocol/experimental-ext-skills/blob/main/docs/threat-model.md)
- [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling)
- [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility)
- [OpenAI API quickstart and tools](https://platform.openai.com/docs/quickstart)
- [Claude tool use](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools)
- [Gemini function calling](https://ai.google.dev/gemini-api/docs/function-calling)

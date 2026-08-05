# Detonate production-readiness and launch plan

Status: active plan, 2026-07-30.

This document defines the shortest credible path from the current Detonate
prototype to an installable, trustworthy, and promotable product. It is the
release and product contract. Detailed component work remains in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), architectural invariants in
[TARGET_ARCHITECTURE.md](TARGET_ARCHITECTURE.md), the code as it stands in
[ARCHITECTURE.md](ARCHITECTURE.md), and live evidence in
[COMPATIBILITY.md](COMPATIBILITY.md).

## 1. Product decision

Keep the trusted control plane in Go.

Detonate is an orchestrator, policy engine, protocol client, evidence
collector, and reporter. Go is a strong fit for a single cross-platform binary,
concurrency, cancellation, static distribution, and Docker lifecycle control.
Target language support belongs in isolated runtime profiles:

```text
Go control plane
├── static artifact readers
├── MCP protocol adapters
├── Docker/Podman sandbox backend
└── runtime profiles
    ├── Node.js
    ├── Python
    ├── Go
    ├── browser/system-tools
    └── additional ecosystems when corpus evidence justifies them
```

Do not rewrite the product in TypeScript or Python to support TypeScript or
Python targets. Add pinned images, manifest adapters, fixtures, and
compatibility tests instead.

### 1.1 Positioning

The product is:

> A detonation chamber for untrusted MCP servers, Agent Skills, and prompts
> that reports both observed risk and exactly how much was tested.

It is not:

- A generic MCP client or replacement for MCP Inspector.
- A replacement for official protocol conformance testing.
- A claim that a no-findings result proves safety.
- A host-based antivirus or malware-analysis VM.
- An LLM judge whose answer changes unpredictably between CI runs.

### 1.2 Primary users

Release decisions should prioritize these users in order:

1. An MCP or skill author testing before publishing.
2. A developer reviewing an MCP/skill dependency before installation.
3. A security engineer adding an AI supply-chain gate to CI.
4. A registry or platform operator evaluating many artifacts.
5. A researcher running optional agentic or model-based evaluations.

## 2. Current truth

The current worktree has a meaningful prototype:

- Docker-isolated stdio MCP execution.
- Static prompt and skill analysis.
- Dynamic skill-script execution.
- Schema-reachable adversarial MCP probes.
- Independent risk and completeness results.
- Per-scenario outcomes and an optional incomplete-coverage gate.
- Lossless MCP content/structured-result normalization and correct `isError`
  handling.
- Bounded `tools/list` pagination.
- Text, JSON, and SARIF output.
- Regression and Docker integration coverage.

It is not production-ready because:

- The worktree, executable entrypoint, and canonical documents are uncommitted.
- There is no current verified public release or installation channel.
- Acquisition can execute target-controlled hooks as root with network access.
- Total, phase, tool, call, output, and disk budgets are incomplete.
- Common fetch/runtime/acquisition/start/inventory/skill-load failures produce
  structured reports; validation, cancellation, and teardown paths do not all
  have equivalent coverage yet.
- Runtime observation is incomplete and relies heavily on target output.
- Modern MCP, Streamable HTTP, authorization, and full primitive coverage are
  missing.
- The current compatibility corpus has not been rerun against the latest
  result model.
- Baselines auto-advance without explicit approval/history.
- The release workflow lacks provenance attestations, SBOM, signature,
  fresh-machine installation verification, and protected release promotion.

## 3. Production-ready and promotable definitions

### 3.1 Production-ready CLI

Detonate is production-ready for local and CI use only when all are true:

- Every requested scenario has one terminal outcome.
- Risk and completeness agree across text, JSON, SARIF, and JUnit.
- Cancellation, timeout, target crash, harness failure, and teardown failure
  cannot yield exit 0.
- Target-controlled code never executes directly on the host.
- Networked acquisition cannot execute untrusted target hooks.
- Every sandbox is removed and removal is verified before reporting success.
- Evidence and protocol buffers are bounded and visibly truncated.
- Supported transports and protocol revisions pass declared conformance and
  compatibility profiles.
- A clean checkout builds, tests, packages, installs, runs `doctor`, and
  completes a smoke scan on every supported operating system.
- Released artifacts have checksums, SBOM, provenance, and a documented
  verification command.

### 3.2 Promotable product

Detonate is promotable only when production readiness is demonstrated with
public proof:

- A five-minute installation-to-first-result path.
- A documented compatibility matrix with immutable target versions.
- Reproducible vulnerable and benign demo fixtures.
- Measured precision/recall on a versioned static corpus.
- A comparison explaining how Detonate complements Inspector, conformance, and
  source-only scanners.
- At least three external users complete the quickstart without maintainer help.
- At least two external CI environments consume the versioned JSON or SARIF
  output.
- Known limitations are visible on the README and release page.
- Security policy, support policy, changelog, migration policy, and issue
  templates exist.

## 4. Release trains

Effort bands below assume one experienced Go engineer and are planning aids,
not promises. A train ships only when its gates pass; elapsed time does not
waive a gate.

| Train | Outcome | Approximate focused effort |
|---|---|---:|
| R0 | Reproducible repository and alpha artifact | 3-5 days |
| R1 | Trustworthy local/CI scan engine | 2-4 weeks |
| R2 | Broad MCP and runtime compatibility | 3-5 weeks |
| R3 | Product-quality CLI, configuration, and evidence UX | 2-3 weeks |
| R4 | Signed beta distribution and operational readiness | 1-2 weeks |
| R5 | Public proof, onboarding, and launch | 1-2 weeks |

The trains overlap only where their dependencies allow it. Do not promote R5
while R1 safety gates remain open.

## 5. R0 - reproducible alpha

Current worktree progress: clean-archive build, install, version, and prompt
smoke checks now cover Linux, macOS, and Windows. Release publication depends
on a separate format, vet, race, test, tracked-entrypoint, and Docker
verification job. Public-project security, support, contribution, changelog,
and issue-intake files are also present. These controls are not active until
the untracked release inputs and workflow changes are reviewed and committed.

### Deliverables

1. Commit the executable, documents, current outcome model, and regressions.
2. Preserve user changes and split the work into reviewable commits:
   - repository/release correction;
   - correctness regressions;
   - outcome/report model;
   - MCP result fidelity and pagination;
   - documentation.
3. Add clean-checkout CI:
   - `git archive` or fresh clone;
   - `go build ./cmd/detonate`;
   - `go install ./cmd/detonate`;
   - `detonate --version`;
   - prompt-only smoke test.
4. Repair public CI and prove the race lane on a clean Linux runner.
5. Add Windows and macOS build lanes; use platform runners for smoke tests where
   container behavior differs.
6. Replace the historical release identity with a new prerelease version. Do
   not reuse or move `v0.1.0`.
7. Add `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, support policy, and
   issue templates.

### Gate

```text
fresh clone
  -> go test ./...
  -> go build ./cmd/detonate
  -> detonate --version
  -> prompt smoke
  -> package archive
  -> install archive elsewhere
  -> repeat smoke
```

No step may depend on an untracked file, developer cache, local tag, or mutable
working directory.

## 6. R1 - trustworthy scan engine

### 6.1 Run-scoped engine

Extract a `Scanner` API from CLI state:

```go
type Scanner interface {
    Scan(context.Context, Request) (Result, error)
}
```

Every run owns immutable configuration, budgets, sandbox handles, collectors,
transcripts, scenarios, and finalization state. No package global may carry
mutable scan data.

### 6.2 State machine

Every scan journals these phases:

```text
validate
resolve
snapshot
fetch
build
start
negotiate
inventory
plan
execute
teardown
finalize
```

Failure jumps to teardown using a fresh bounded cleanup context. Finalization
occurs after verified teardown, not before it.

### 6.3 Budgets and cancellation

Implement configurable nested budgets:

| Budget | Initial default | Required behavior |
|---|---:|---|
| Total scan | 10 minutes | Root deadline for all non-cleanup work |
| Resolve/fetch | 2 minutes | No unbounded remote operation |
| Build | 5 minutes | Offline target-code build |
| Start/negotiate | 45 seconds | Explicit startup timeout |
| Inventory | 45 seconds | Includes all bounded pages |
| Per tool | 60 seconds | Covers baseline plus generated cases |
| Per call | 10 seconds | Cannot exceed remaining tool/scan budget |
| Teardown | 20 seconds | Fresh context, force removal, verify absence |
| Evidence | 32 MiB total | Ring buffers and truncation accounting |

Defaults require corpus calibration. The invariant is more important than the
exact number: child deadlines cannot exceed the remaining root budget.

Cancellation must:

- stop scheduling new scenarios;
- mark the active scenario `timeout` or `skipped` with cause;
- mark pending required scenarios explicitly;
- close the protocol session;
- preserve collectors through teardown;
- verify sandbox removal;
- return incomplete/failed, never success.

### 6.4 Bounded evidence

Bound and report:

- stdout/stderr bytes;
- dropped bytes;
- protocol frame size;
- JSON/schema depth and bytes;
- tool/item/page count;
- content blocks per result;
- individual result bytes;
- total redacted transcript bytes;
- temp disk and writable-volume use.

Truncation changes completeness. It cannot be a debug-only log line.

### 6.5 Failure taxonomy

Every failure includes:

- stable code;
- phase;
- target or harness ownership;
- retryability;
- human remediation;
- sanitized underlying cause.

Examples:

```text
DET-RUNTIME-MISSING
DET-MCP-NEGOTIATION
DET-MCP-CURSOR-LOOP
DET-SANDBOX-TEARDOWN
DET-ACQUIRE-HOOK-BLOCKED
DET-COVERAGE-TRUNCATED
```

Early failures must still emit valid `detonate.report/v1` JSON/SARIF/JUnit
documents with `risk=not_assessed`.

### 6.6 Safe acquisition

Replace networked package-manager execution with three phases:

1. Fetch immutable source and dependency artifacts with network access but no
   target code execution.
2. Verify and inventory the artifact set.
3. Build/install with target hooks allowed only in a network-disabled sandbox.

Requirements:

- Pin source revisions and container image digests.
- Reject path, symlink, junction, and build-context escapes.
- Mount source read-only.
- Keep dependency caches per origin and content identity.
- Never expose host credentials, Docker socket, SSH agent, package tokens, or
  user home.
- Make requested egress allowlists explicit and report-visible.

If an ecosystem cannot guarantee inert fetching, fetch packages as data and
perform all resolution/build execution offline.

### 6.7 Runtime evidence and teardown

- Start Docker event collection before the container.
- Capture start, die, OOM, kill, exit code, and removal.
- Record process/container exit separately from tool results.
- Treat teardown failure as a safety failure.
- Use unique labels and verify that orphan reaping cannot touch unrelated
  containers.
- Add crash, hang, fork bomb, OOM, output flood, disk flood, and ignored-signal
  fixtures.

### R1 gate

- No false-success fixture exits 0.
- Every failure path emits a valid machine report.
- Resource-exhaustion fixtures stay inside configured host budgets.
- Forced cancellation leaves no labeled container, volume, or network.
- Resolver containment passes Linux and Windows path fixtures.
- Networked phases execute no target-controlled hooks.

## 7. R2 - protocol and ecosystem compatibility

### 7.1 MCP baseline

Upgrade behind an adapter to the stable official Go SDK revision supporting the
declared protocol matrix. Do not scatter SDK types through the engine.

Required transports:

- stdio;
- Streamable HTTP;
- stateless modern HTTP;
- legacy compatibility negotiation;
- explicit unsupported result for anything outside the matrix.

Required protocol surfaces:

- tools and tool annotations;
- prompts and completions;
- resources and resource templates;
- structured and non-text content;
- progress and cancellation;
- extensions;
- authorization and discovery relevant to supported revisions;
- multi-round-trip behavior where supported;
- change/subscription behavior where supported.

### 7.2 HTTP and authorization safety

- HTTPS by default for non-loopback remote targets.
- Reject private, loopback, link-local, metadata, and reserved addresses unless
  an explicit development profile allows them.
- Validate every redirect hop.
- Pin DNS resolution or route discovery through a policy-enforcing proxy.
- Redact authorization headers, cookies, query tokens, and OAuth material.
- Store token references in the OS credential store or environment references;
  never write raw secrets to project configuration or evidence.
- Separate read-only discovery credentials from mutation-capable credentials.
- Require explicit approval for any remote write/destructive scenario.

### 7.3 Runtime profiles

Ship pinned profiles, not an ever-growing universal image:

| Profile | Purpose |
|---|---|
| `static` | No Docker; artifacts, prompts, manifests, and schemas only |
| `node` | Node/npm/pnpm targets |
| `python` | Python/pip/uv targets |
| `go` | Go build and Go MCP servers |
| `system` | Git and selected audited system binaries |
| `browser` | Playwright/browser servers with stricter limits |
| `auto` | Detect and select one declared profile |

Each report contains profile name, image digest, toolchain versions, and
unsupported dependencies. Users can add a custom image only with a visible
trust warning and recorded digest.

### 7.4 Compatibility and conformance

Use three separate suites:

1. Official conformance for specification behavior.
2. First-party fault-injection fixtures for hostile and malformed behavior.
3. Real compatibility corpus for packaging/runtime shapes.

Every corpus row records:

- immutable source or image digest;
- transport and protocol revision;
- runtime profile;
- required scenarios;
- expected failures;
- duration and evidence location;
- Detonate commit and report schema.

Pull requests run a deterministic subset. Nightly runs the full pinned corpus.
Remote public demos are informational and cannot fail a release by changing
outside the repository.

### R2 gate

- Declared protocol/transport cells pass conformance.
- Everything, Memory, Filesystem, Git, Fetch, Time, one Go server, one remote
  HTTP fixture, and representative skills meet their declared coverage.
- Unsupported targets report a stable reason instead of crashing.
- Compatibility results are generated by a versioned harness, not copied from
  terminal history.

## 8. R3 - CLI and configuration product

### 8.1 Command model

Keep the convenient positional form as an alias:

```text
detonate <target> [scan options]
```

Add an explicit, discoverable command tree:

```text
detonate scan <target>          Static + selected dynamic profile
detonate inspect <target>       Static/inventory-only, Docker optional
detonate doctor                 Environment and sandbox self-test
detonate explain <report>       Explain findings, coverage, and remediation
detonate report validate <file> Validate/migrate report schema
detonate baseline show <target>
detonate baseline diff <target>
detonate baseline approve <target>
detonate profiles list
detonate profiles show <name>
detonate corpus run <suite>     Maintainer/CI compatibility command
detonate version
```

Do not expose host execution as a convenience flag.

### 8.2 Core scan flags

Stable v1 flags:

```text
--profile static|standard|deep|agentic
--config <file>
--cmd <sandbox command>
--path <repository subpath>
--transport auto|stdio|http
--url <streamable-http endpoint>
--runtime auto|node|python|go|system|browser
--format text|json|sarif|junit
--out <file>
--evidence-dir <directory>
--fail-on notable|critical|never
--fail-incomplete
--timeout <duration>
--phase-timeout <phase=duration>
--tool-timeout <duration>
--call-timeout <duration>
--network none|emulated|allowlist
--allow-host <hostname>
--baseline off|compare|require
--record <bundle>
--replay <bundle>
--quiet
--no-color
--progress auto|plain|json|off
```

Advanced resource limits belong in configuration and a clearly grouped
`--limit-*` namespace rather than cluttering the normal help screen.

### 8.3 Configuration contract

Configuration precedence:

```text
CLI flags
  > environment references
  > project detonate.yaml
  > user config
  > profile defaults
```

Example:

```yaml
schema: detonate.config/v1
profile: standard
target:
  transport: auto
runtime:
  profile: auto
budgets:
  total: 10m
  tool: 60s
  call: 10s
network:
  mode: none
coverage:
  fail_incomplete: true
gates:
  fail_on: notable
evidence:
  directory: .detonate/evidence
  redact: true
llm:
  enabled: false
```

Rules:

- Unknown fields are errors.
- Configuration has a schema version and migration path.
- Secrets are references such as `${ENV:OPENAI_API_KEY}` or credential-store
  IDs, never literals.
- `detonate config validate` reports all errors in one pass.
- `detonate config effective` prints the redacted resolved configuration.

### 8.4 Human output

Default output should answer five questions in this order:

```text
Target       github.com/example/server@<sha>
Profile      standard / node / stdio / protocol 2026-07-28
Risk         suspicious
Completeness partial (11/14 required scenarios)
Decision     blocked by finding threshold and incomplete coverage
```

Then show:

1. Findings with rule ID, evidence, phase, and remediation.
2. Incomplete scenarios and reasons.
3. Artifact/runtime identity.
4. Evidence/report paths.
5. Exact reproduction command.

Progress must remain on stderr when stdout contains JSON/SARIF/JUnit. Support
plain progress for CI and interactive progress for terminals.

### 8.5 Errors and remediation

Bad:

```text
initialize: EOF
```

Required:

```text
DET-RUNTIME-MISSING during start
The selected Python profile does not contain the `git` executable required by
this server.

Try:
  detonate scan <target> --runtime system

Report: risk=not_assessed completeness=failed
```

Errors must be actionable without `--debug`. Debug mode adds sanitized protocol
and sandbox diagnostics but never prints secrets.

### 8.6 Baselines

Stop auto-advancing trust:

- First scan proposes a baseline.
- `baseline approve` records actor, time, reason, source digest, tool hashes,
  Detonate version, and profile.
- A changed baseline is a finding until approved.
- CI can import/export a signed baseline file.
- History is append-only and reviewable.

### 8.7 First-run experience

`detonate doctor` must test:

- binary and configuration version;
- Docker/Podman availability;
- daemon/rootless/VM status;
- CPU, memory, disk, and architecture;
- runtime image presence and digest;
- proxy/network configuration;
- sandbox start, network denial, read-only mount, non-root uid, limits, and
  verified cleanup;
- optional Ollama/provider configuration without sending user data.

The first dynamic scan explains image downloads and estimated disk/time before
pulling. Static scans must work without Docker.

### R3 gate

- New user completes install, doctor, and first scan in under five minutes.
- Help examples are tested in CI.
- Shell completion exists for PowerShell, Bash, Zsh, and Fish.
- JSON stdout is never corrupted by progress output.
- Every exit code and flag has a regression test.
- A one-version deprecation path exists for renamed flags.

## 9. Optional LLM and agentic testing

LLM support is an additional scenario generator and semantic evaluator, not
the authority for deterministic risk.

Provider interface:

```go
type Provider interface {
    Complete(context.Context, Request) (Response, error)
    Capabilities(context.Context) ProviderCapabilities
}
```

Delivery order:

1. Deterministic record/replay provider.
2. Ollama for private local testing.
3. OpenAI-compatible HTTP adapter.
4. Anthropic adapter.
5. Gemini adapter.

Requirements:

- Explicit opt-in per scan.
- Provider/model/version and sampling parameters recorded.
- Prompt and response redaction.
- Cost/token/request budgets.
- No secrets in bundles.
- Repeated trials and raw counts for statistical claims.
- Provider failures reduce agentic completeness but cannot erase deterministic
  findings.
- CI defaults to replay; live hosted providers belong in optional/nightly jobs.

## 10. R4 - distribution and operations

### 10.1 Release pipeline

Use a pinned release toolchain, whether custom Actions or GoReleaser:

- Cross-platform archives for Linux, macOS, and Windows.
- Version metadata from the immutable tag.
- Deterministic filenames and normalized archive timestamps.
- SHA-256 checksums.
- SPDX or CycloneDX SBOM.
- Build provenance attestation.
- Signed checksum or Sigstore bundle.
- Release notes generated from reviewed changelog entries.
- Installation and smoke verification on fresh platform runners.
- Promotion only from a protected environment after all required CI checks.

Pin GitHub Actions to commit SHAs and use least-privilege permissions. The
release job must not merely rerun a subset after a tag; it must promote the
exact commit/artifacts whose required CI matrix passed.

### 10.2 Distribution order

1. GitHub prerelease archives.
2. `go install`.
3. Stable GitHub release.
4. Homebrew tap.
5. Scoop and winget.
6. Optional signed CI container containing Detonate, not a Docker socket.

Do not make `curl | sh` the primary installation path. Do not publish package
manager entries until automated clean-machine install/uninstall tests exist.

### 10.3 Runtime images

- Publish multi-architecture runtime images separately from the CLI.
- Pin every base and package dependency.
- Generate image SBOM and provenance.
- Scan images and define patch/rebuild policy.
- Refer to images by digest in reports and profiles.
- Keep the default download small; fetch specialized profiles on demand.
- Define a compatibility window between CLI and runtime-profile versions.

### 10.4 Operations

For local CLI:

- No telemetry by default.
- Opt-in anonymous diagnostics only after a public data dictionary exists.
- Local logs and evidence have retention and deletion commands.
- Crash reports are sanitized and user-controlled.

For a future hosted service:

- Separate control plane from isolated worker pool.
- No Docker socket exposure to jobs.
- Per-tenant queues, quotas, encryption, retention, and audit logs.
- Stronger isolation such as gVisor/Kata/Firecracker.
- Abuse controls and prohibited-target policy.
- Incident response, backup/restore, key rotation, and regional data policy.

Do not launch hosted multi-tenant scanning on the local Docker architecture.

### R4 gate

- Every artifact verifies with documented checksum/provenance commands.
- Fresh Windows, macOS, and Linux installs pass doctor and smoke scans.
- Upgrade and rollback between the prior two versions are tested.
- A failed release cannot partially publish inconsistent channels.
- Runtime image CVEs and dependency updates have an owner and response policy.

## 11. R5 - proof and promotion

### 11.1 Launch assets

Create:

- A 90-second terminal demo.
- A five-minute quickstart.
- One intentionally vulnerable MCP server.
- One hardened equivalent showing a no-findings + complete result.
- One real skill example with static and dynamic coverage.
- CI examples for GitHub Actions and generic shells.
- A report-schema integration example.
- A comparison table against Inspector, conformance, and source-only scanners.
- A public compatibility dashboard generated from pinned corpus results.
- Architecture and threat-model diagrams.

### 11.2 Honest claims

Allowed after evidence:

- "Runs supported MCP servers and skills inside a restricted sandbox."
- "Reports risk and coverage separately."
- "Detects demonstrated traversal, command-injection, prompt-injection, and
  runtime-behavior fixtures."
- "Supports the protocol/transport cells shown in the compatibility matrix."

Not allowed:

- "Makes MCP safe."
- "Detects all malicious servers."
- "Supports every MCP server."
- "Docker means the host cannot be compromised."
- "No findings means safe."

### 11.3 Adoption loop

1. Recruit 3-5 design partners.
2. Observe installation and first scan without coaching.
3. Record every failure stage and time-to-remediation.
4. Prioritize repeated compatibility shapes, not one-off popularity.
5. Publish fixed issues and corpus additions.
6. Add a `detonate-tested` badge only when it links to immutable report
   evidence, profile, version, and completeness.

### 11.4 Product metrics

Track locally in release evaluation, not via mandatory telemetry:

- install success by supported platform;
- doctor success;
- time to first report;
- scan completion rate by runtime profile;
- incomplete/failure causes;
- median and p95 duration;
- false-positive/false-negative corpus rates;
- orphaned-sandbox count;
- report-schema compatibility;
- external issue resolution time.

### R5 gate

- Quickstart succeeds for external users.
- Public demos reproduce from clean machines.
- Compatibility dashboard is generated, dated, and versioned.
- At least one external CI integration gates on both risk and completeness.
- README claims match the current release evidence.

## 12. CI and test architecture

### Pull-request fast lane

- gofmt, vet, static analysis, unit tests.
- Report/config schema golden tests.
- Hostile parser and protocol fixtures.
- Clean-checkout build and install.
- CLI help/example tests.

### Pull-request Docker lane

- Sandbox policy and teardown.
- Offline acquisition fixtures using local package registries.
- Node, Python, and Go runtime smoke targets.
- Race detector.
- Resource-exhaustion tests with strict outer timeouts.

### Nightly lane

- Official conformance for declared cells.
- Full pinned compatibility corpus.
- Multi-architecture runtime images.
- Static precision/recall corpus.
- Dependency/image vulnerability scans.
- Optional Ollama live subset; hosted providers only when explicitly enabled.

### Release lane

- Required PR and nightly evidence green for the release commit.
- Fresh-platform archive installation.
- Package-manager installation.
- Upgrade/rollback.
- SBOM, provenance, signatures, checksums.
- Release-candidate soak before stable promotion.

## 13. Issue/epic breakdown

Create issues in this dependency order:

1. Track and commit release inputs.
2. Clean-checkout build/install CI.
3. Run-scoped engine and state journal.
4. Total/phase/tool/call budgets.
5. Structured early-failure reports. Fetch, runtime preflight, acquisition,
   MCP startup/inventory, and skill-load failures are implemented in the
   current worktree; validation, cancellation, and teardown paths remain.
6. Bounded evidence and truncation completeness.
7. Verified event collection and teardown.
8. Resolver/snapshot containment.
9. Inert fetch plus offline build.
10. Runtime-profile manifest and pinned images.
11. Versioned config and profiles.
12. Stable CLI command tree and error taxonomy.
13. Baseline approval/history.
14. MCP SDK adapter upgrade.
15. Streamable HTTP and authorization safety.
16. Full primitive inventory and conformance.
17. Schema-aware generation and controlled service emulators.
18. Realistic skill invocation manifests.
19. Doctor and first-run UX.
20. Release/SBOM/provenance/signing.
21. Fresh-machine installers.
22. Public corpus dashboard and launch assets.
23. Ollama record/replay.
24. Hosted LLM adapters.

Each issue must include:

- user-visible outcome;
- threat/failure being addressed;
- non-goals;
- acceptance tests;
- report/config/CLI compatibility impact;
- documentation changes;
- corpus row or fixture proving it.

## 14. Release scorecard

Update this table in every release-candidate pull request:

| Area | Current | Stable requirement | Evidence |
|---|---|---|---|
| Repository | Dirty worktree; untracked release inputs | Clean tracked release commit | Clean-checkout CI |
| Results | Successful scans have risk/completeness | All early/failure paths modeled | Golden failure reports |
| Budgets | Partial/fixed timeouts | Nested enforced budgets | Hang/flood fixtures |
| Acquisition | Hooks may run root+network | Inert fetch + offline execution | Malicious hook fixture |
| Teardown | Strong container close path | Event-backed verified transaction | Kill/OOM/cancel fixtures |
| MCP stdio | Legacy/current subset | Declared conformance cells green | Conformance report |
| MCP HTTP | Unsupported in CLI | Streamable HTTP + auth safety | Local HTTP fixture |
| Skills | Static + basic scripts | Invocation manifests + dependencies | PDF/DOCX corpus |
| Reports | Text/JSON/SARIF | Plus JUnit, provenance, migrations | Schema/golden tests |
| CLI | Useful prototype | Stable commands/config/doctor | UX and help tests |
| Packaging | No usable release | Signed verified multi-platform release | Fresh-runner tests |
| Promotion | Internal evidence | Public reproducible proof | Dashboard and demos |

## 15. Stop/go rules

Continue investment when:

- External users reproduce value beyond protocol inspection.
- Detonate finds issues or coverage gaps that Inspector/conformance alone do not
  answer.
- Compatibility failures cluster into reusable runtime/profile improvements.
- Precision remains high enough that users keep the CI gate enabled.

Re-scope when:

- Most demand is only for basic MCP inspection already served elsewhere.
- Every new server requires a bespoke image with no reusable shape.
- Dynamic findings cannot be made reproducible.
- The maintenance cost of current MCP revisions exceeds user value.

The preferred re-scope is a narrower, excellent local/CI detonation engine, not
an unmaintainable promise to support every server, language, and model.

## 16. First stable release gate

The first stable tag may be created only when:

1. R0 is complete.
2. Every R1 gate passes.
3. The declared R2 compatibility cells pass and are published.
4. R3 CLI/config/doctor contracts are tested.
5. R4 release artifacts verify on fresh platforms.
6. No unresolved critical security issue exists.
7. Documentation and claims match the release commit.
8. The release candidate has completed an external-user quickstart.

Until then, versions must be clearly marked alpha or beta.

## 17. Primary external references

- [MCP specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [Official MCP conformance framework](https://github.com/modelcontextprotocol/conformance)
- [Official MCP Inspector](https://github.com/modelcontextprotocol/inspector)
- [Official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk)
- [Official MCP Registry moderation policy](https://modelcontextprotocol.io/registry/moderation-policy)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub build provenance guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [GoReleaser configuration](https://goreleaser.com/customization/)
- [GoReleaser signing](https://goreleaser.com/customization/sign/sign/)

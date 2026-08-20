# Detonate implementation plan

Status: implementation in progress, 2026-07-30. **Superseded for current
state and near-term priorities by [STATUS.md](#) <!-- deleted from the repo --> and
[PRODUCTION_GRADE.md](#) <!-- deleted from the repo --> at the repository root** —
those are checked against the running binary as of 2026-08-05; `v0.1.0` is
tagged and this document's "not release-ready" framing below is stale.
This file remains the record of the longer-horizon architectural phases.

This plan implements [TARGET_ARCHITECTURE.md](TARGET_ARCHITECTURE.md). It is
ordered to stop false confidence and release failures before adding features.
For the code as it stands today, see [ARCHITECTURE.md](../ARCHITECTURE.md).

The cross-phase release, CLI, packaging, and promotion contract is tracked in
[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md).

The focused scenario contract for activating and testing MCP tools, Agent
Skills, prompts, and optional LLM replays is in
[TEST_SCENARIO_PLAN.md](TEST_SCENARIO_PLAN.md).

## 1. Current evidence (historical — see STATUS.md for current)

The repository is a useful prototype with meaningful sandbox and protocol test
coverage, but it is not release-ready.

Verified locally:

- `go test -count=1 ./...` passes, including Docker integration packages.
- The official MCP Everything server is cloned, built, sandboxed, and enumerated
  (14 tools).
- The official Memory server is cloned, built, and run through the current
  probe engine (9 tools), but eight tools are skipped because their schemas do
  not have top-level string fields.
- Raw prompt injection signatures work.
- Ollama `qwen3.5:9b` returns a valid structured function call.

Release/correctness blockers:

- `cmd/detonate/main.go` is now visible after anchoring the binary ignore
  patterns, but it remains untracked and absent from a clean checkout.
- A clean checkout therefore cannot build the advertised CLI or release job.
- The historical `v0.1.0` release run passed tests and failed its build; GitHub
  has no release or current remote tag, while the local tag is 19 commits behind
  `main`.
- Public `main` CI is red in its race-test step, although the equivalent clean
  Go 1.25 archive run passes locally; the CI-only/environmental cause remains
  open.
- Historical files under `detonate-docs-local` contradict the code and each
  other; they are now marked non-canonical.
- The local `testmatrix.sh` is truncated and never runs its matrix.
- Successful prompt, skill, and MCP scans separate risk and completeness.
  Common fetch/runtime/acquisition/start/inventory/skill-load failures now
  preserve the same structured contract; validation, cancellation, and
  teardown paths still need equivalent coverage.
- The `ModuleNotFoundError`/`ENOTFOUND` false positive has a regression fix.
- Skill scripts run without dependencies/arguments; exit and timeout status are
  assessed, but invocation coverage remains incomplete.
- Acquisition executes target-controlled hooks/builds as root while network is
  enabled; the CLI now states this honestly, but the boundary remains unsafe.
- Normal monitoring relies primarily on target stderr; Docker event monitoring
  is not wired into scans.
- Only legacy-generation stdio tools are tested. Current MCP also requires a
  modern protocol/transport strategy.

## 2. Delivery rules

Each phase has:

1. A user-visible outcome.
2. Tests that fail before the change and pass after it.
3. Versioned documentation/report changes.
4. No unqualified capability claim until its compatibility corpus passes.

Priority definitions:

- **P0**: release, safety, or false-confidence blocker.
- **P1**: required for a trustworthy initial release.
- **P2**: broad compatibility and adoption.
- **P3**: advanced/experimental capability.

Size is relative engineering effort: S (days), M (roughly one to two weeks),
L (multiple weeks). It is not a calendar commitment.

## 3. Phase 0 — stop the false release and false results

Priority P0, size M.

### 3.1 Track the executable and prove clean-checkout builds

Worktree progress: the ignore correction, build-info version fallback,
cross-platform `git archive` build/install/smoke matrix, and release
verification dependency are implemented locally. The gate remains open until
the entrypoint and workflow changes are committed and pass on hosted runners.

Tasks:

- Anchor binary ignore rules to repository-root build outputs
  (`/detonate`, `/detonate.exe`) instead of ignoring every path named
  `detonate`.
- Add `cmd/detonate/main.go` to Git.
- Add `go build ./cmd/detonate` and `go install ./cmd/detonate` to CI.
- Use `debug.ReadBuildInfo` as the version fallback so `go install @<tag>`
  reports its module version even without release-workflow linker flags.
- Add a CI job that builds from `git archive` or a fresh checkout so ignored or
  untracked local files cannot mask missing release inputs.
- Block release workflow execution unless the commit's CI conclusion is green.

Acceptance:

- `git ls-files cmd/detonate/main.go` returns the file.
- A clean checkout builds on Linux and Windows.
- `go install github.com/m4vic/detonate/cmd/detonate@<tag>` works from outside
  the repository.
- The installed binary's `--version` equals the requested module version/tag,
  not `dev`.

### 3.2 Fix known false positives and false success

Tasks:

- Replace broad stderr substring signatures with typed, line-aware matchers.
  Add a regression proving `ModuleNotFoundError` does not match Node
  `ENOTFOUND`.
- Scope warning/negation handling to the matched action and clause, not the
  entire line. A concealment phrase such as “never tell the user” must not
  suppress a credential-access instruction earlier on that line.
- Make skill script exit status, timeout, missing interpreter, and missing
  dependency explicit scenario outcomes.
- Stop saying a failed script “ran with no observable misbehaviour.”
- Change risk label `clean` to `no findings` in human output where practical.
- Run a minimum deterministic poisoning rule set over MCP tool names,
  descriptions, schemas, annotations, and metadata before any MCP security
  release claim.

Acceptance:

- Anthropic `skills/pdf` no longer receives network findings for missing Python
  modules.
- A script exiting non-zero cannot yield `completeness=complete`.
- Detector fixtures include positive and negative examples per signature.
- The recorded raw prompt emits override, credential-access, and concealment
  findings; its concealment wording cannot hide the credential action.
- A hostile tool description cannot enumerate to an unqualified no-findings
  result without being analyzed.

### 3.3 Establish canonical documentation and compatibility evidence

Tasks:

- Keep architecture, plan, and compatibility results under repository `docs/`.
- Mark local notes as non-canonical.
- Correct CLI/help/status text that says acquisition does not execute the
  target; distinguish dependency fetch, target-controlled build hooks, and
  detonation.
- Repair or replace `testmatrix.sh`; run commands from a versioned Go test
  harness where cross-platform behavior matters.
- Every matrix row stores an immutable target ID or timestamped remote snapshot,
  command, exit state, coverage, duration, and log/evidence location.

Acceptance:

- Documentation contains no milestone claim contradicted by code.
- CLI and README make the same acquisition-execution and coverage claims.
- The documented reproduction command actually invokes the matrix.

### 3.4 Contain resolution before any target code runs

Tasks:

- Replace string-prefix subpath checks with `filepath.Rel` containment.
- Resolve symlinks/junctions at the immutable snapshot boundary and reject any
  selected target/build context that escapes it.
- Require explicit configuration before widening a monorepo package to an
  ancestor build context; copy only declared required files where possible.
- Add sibling-prefix, `..`, symlink/junction, case-folding, and Windows path
  fixtures.

Acceptance:

- A requested subpath cannot resolve to a sibling-prefix directory or outside
  the immutable snapshot on Linux or Windows.
- Networked acquisition code never receives undeclared sibling source.

### Phase 0 release gate

Do not create a version tag until every Phase 0 acceptance test passes.

## 4. Phase 1 — trustworthy outcomes and bounded evidence

Priority P0/P1, size M.

### 4.1 Introduce scenario and completeness models

Implemented in the current worktree:

- Typed scenario outcomes, independent risk/completeness aggregation, and
  `detonate.report/v1`.
- Per-tool MCP probe coverage and per-script skill coverage on successful scans.
- Lossless normalized MCP tool results: every content block, structured output,
  and `isError` is retained for deterministic inspection. A benign
  `isError=true` response becomes `target_error`, not pass or transport failure.
- Bounded `tools/list` pagination across every MCP enumeration path, with
  cursor-loop detection plus 64-page and 4096-item ceilings.
- Structured fetch, runtime, acquisition, MCP startup/inventory, and skill-load
  failures in JSON and SARIF, with stable phase/code/retryability fields and a
  failed scenario that prevents false-clean output.
- Text, JSON, and SARIF risk/completeness fields.
- Optional `--fail-incomplete` gate with exit code 4.
- Regression coverage for unsupported tools, network-dependent tools,
  unsupported interpreters, non-zero script exits, and partial CLI results.

Still required before this section is complete: cancellation/budget
enforcement, bounded transcript persistence, remaining validation/teardown
failure paths, and compatibility-corpus acceptance runs.

Tasks:

- Add `ScenarioResult` with stable ID and outcome:
  `pass|finding|skipped|unsupported|timeout|target_error|harness_error|teardown_error`.
- Add separate `Risk` and `Completeness` aggregates.
- Track required versus optional scenarios per profile.
- Add JSON schema version `detonate.report/v1`.
- Add a configurable incomplete-coverage exit gate (planned exit 4).
- Preserve every MCP tool-result content type and model `isError=true` as a
  tool/target outcome rather than losing it or treating it as transport error.
- Follow `nextCursor` for every current list operation with loop, item, and
  deadline budgets; truncation makes coverage incomplete.
- Propagate cancellation as an incomplete/cancelled scan, never as successful
  partial events.
- Replace the fixed 60-second container lifetime plus per-call timeouts with an
  explicit total scan budget, per-phase budget, per-tool budget, and per-call
  budget that the scheduler actually enforces.

Acceptance:

- The current Memory scan reports `no_findings + partial`, not clean, because
  eight of nine tools are not probed.
- A network-dependent tool, unsupported transport, or missing runtime is
  visible in coverage.
- JSON/text/SARIF agree on risk and completeness.
- A paginated fixture cannot hide tools, and a compliant `isError=true` result
  cannot be mistaken for a successful benign response.
- A multi-tool fixture cannot outlive its total budget or report complete after
  cancellation; pending scenarios retain explicit skip/timeout causes.

### 4.2 Wire runtime evidence

Tasks:

- Start Docker event collection before each container and fold lifecycle,
  exit, OOM, and kill events into the trace.
- Start the monotonic trace before resolution/acquisition so every phase has
  non-negative, correctly ordered timing.
- Capture explicit process/container exit status in MCP and skill sessions.
- Add bounded ring buffers for stdout/stderr with total byte and dropped-byte
  counters.
- Bound MCP frame size, tool/item count, description/schema depth and bytes,
  content blocks, individual result size, and total redacted transcript bytes.
- Add before/after snapshots of writable tmpfs/volumes.
- Add hard CPU quota, memory+swap ceiling, ulimits, and disk/tmpfs budgets.
- Verify teardown and report failures as safety errors.

Acceptance:

- OOM, PID exhaustion, timeout, normal exit, crash, and forced teardown have
  distinct tests.
- A target writing unlimited stderr cannot grow host memory without bound.
- Oversized MCP metadata or tool output terminates only the responsible
  scenario with bounded evidence and incomplete coverage, not host OOM.
- No test leaves a `detonate-*` container or volume.

### 4.3 Deterministic reports and provenance

Tasks:

- Sort SARIF rules/results and every map-derived output.
- Record target hash/commit, image digest, Docker/platform versions, policy
  hash, command, config hash, rule/probe versions, and coverage.
- Bound and redact evidence consistently.
- Add golden JSON/SARIF tests and schema validation.
- Replace automatic baseline overwrite with immutable candidates and explicit
  `baseline approve`; use atomic writes, locking, append-only history, and
  export/import for CI.

Acceptance:

- Two identical scans produce byte-identical JSON/SARIF except documented
  timestamps/IDs.
- Report consumers can distinguish target failure from a finding.
- A suspicious or incomplete scan cannot silently become the next trusted
  baseline.

### 4.4 Collapse crash cascades

Tasks:

- Add server-liveness state to the scheduler.
- When one probe kills a server, record the causal scenario once and mark
  dependent scenarios skipped with that cause.
- Add optional per-scenario fresh-process isolation for crash-prone targets.

Acceptance:

- One server crash never becomes N independent crash findings.

### 4.5 Extract a run-scoped engine and public Go API

Tasks:

- Move CLI orchestration to a terminal-independent `ScanRequest → ScanResult`
  engine exposed by the root `detonate` package.
- Keep output writers, configuration, buffers, deadlines, and dependencies
  per scan; remove mutation of shared `cli.App` state.
- Add concurrent scanner tests plus CLI/library parity golden tests.

Acceptance:

- Two concurrent scans cannot redirect or discard each other's output, policy,
  evidence, or cancellation.
- CLI and Go API return the same typed result for the same request.

## 5. Phase 2 — safe, reproducible acquisition and runtime compatibility

Priority P1, size L.

### 5.1 Split fetch from target-code execution

Tasks:

- Implement content-addressed artifact storage.
- npm fetch/install dependencies with lifecycle scripts disabled.
- Download Python wheels/sdists without importing/building target code.
- Resolve Go modules with checksums and a pinned toolchain.
- Run build/lifecycle hooks only in a second, network-off sandbox.
- Record dependency integrity, lockfile, SBOM, and build outputs.
- Treat builds requiring network as incomplete unless a scenario explicitly
  provides an isolated emulator.

Acceptance:

- A malicious postinstall cannot reach the public network.
- Build hooks are still observed and reported.
- Re-running an immutable target uses identical inputs or reports drift.

### 5.2 Add ecosystem profiles

Order:

1. Node: npm lockfiles, prebuilt packages, TypeScript, monorepos.
2. Python: wheels, pyproject/build backends, `uv`/console scripts.
3. Go: `go.mod`, main-package detection, cross-build inside a pinned image.
4. pnpm/yarn/bun, then system-dependency and browser profiles.

Tasks:

- Replace filename guesses with `RuntimePlan` objects.
- Add `--image`/profile only through validated config, with the resulting
  security delta printed and recorded.
- Provide images/profiles for `git`, Chromium/Playwright, and database client
  dependencies without building one giant permissive image.
- Set correct runtime image for JS/TS skill scripts.

Acceptance:

- GitHub's Go MCP server at least builds, starts, and inventories without host
  credentials.
- Official Git/Filesystem/Fetch/Time servers run in purpose-built profiles.
- A missing system dependency is `unsupported` with remediation, not a bare
  EOF or clean result.

### 5.3 Pin and verify images

Tasks:

- Resolve image tags to digests and store them in versioned profile manifests.
- Verify image architecture and toolchain versions.
- Add an update job that proposes digest changes and runs the full corpus.

Acceptance:

- Every report names exact image digests.
- Image updates cannot land without compatibility and sandbox tests.

## 6. Phase 3 — versioned static analysis

Priority P1/P2, size M.

### 6.1 Artifact graph

Tasks:

- Inventory every file, symlink, executable, reference, asset, and manifest
  within bounded limits.
- Resolve paths after symlinks and prevent root escape.
- Add Unicode/control-character, encoding/obfuscation, secret, executable, URL,
  command, and dependency checks.
- Emit explicit skipped-file coverage.

### 6.2 Rule engine

Tasks:

- Stable rule IDs, versions, severity, confidence, target kinds, references,
  and positive/negative fixtures.
- Context-aware line/token matching instead of one broad regex list.
- Suppressions with reason, owner, scope, and expiry.
- Calibration corpora and false-positive/false-negative budgets.

### 6.3 MCP/skill/prompt rules

Tasks:

- Analyze tool descriptions, input/output schemas, annotations, defaults,
  headers, resources, prompts, and metadata.
- Compare skill declarations with explicit commands, scripts, references, and
  assets.
- Track progressive disclosure.
- Preserve byte offsets for SARIF locations.

Acceptance:

- Every critical rule has at least one exploit fixture and multiple benign
  counterexamples.
- Corpus regressions fail CI.

## 7. Phase 4 — current MCP protocol and transport coverage

Priority P1/P2, size L.

### 7.1 Introduce protocol/transport boundaries

Tasks:

- Create normalized MCP inventory types independent of the Go SDK.
- Implement `stdio`, `streamable-http`, and optional deprecated `sselegacy`
  transports behind one interface.
- Record negotiated protocol era/revision.
- Support dual-era discovery/fallback behavior.

Dependency strategy:

- Keep `v1.5.0` behavior covered while interfaces land.
- Test stable Go SDK `v1.7.0` in a branch/matrix.
- Upgrade the default after the legacy and modern corpus/conformance matrices
  pass; do not assume the SDK upgrade alone provides product compatibility.

### 7.2 Full primitive inventory

Tasks:

- Tools, resources, resource templates, prompts, pagination, and change
  notifications/subscriptions.
- Version/capability/extension discovery.
- Modern input-required flows; legacy roots/sampling/elicitation as applicable.
- Tasks and MCP Apps as optional extension modules.
- Skills over MCP behind an experimental flag until its SEP stabilizes.

Acceptance:

- Everything server coverage includes prompts and resources, not only 14 tools.
- Unsupported advertised capability is a protocol result.

### 7.3 Official conformance suite

Tasks:

- Run `@modelcontextprotocol/conformance` against Detonate's client behaviors
  and selected server corpus.
- Build a first-party Go fault-injection server with pinned legacy stdio and
  modern stateless Streamable HTTP modes.
- Import machine-readable results as scenario outcomes.
- Maintain expected-failure baselines that fail when stale.
- Pin conformance and Inspector versions; migrate the provisional Inspector
  `0.21.2` evidence to the current v2 CLI before it becomes a release row.
- Keep MCP Inspector as a manual/debugging aid, not the CI oracle.

Acceptance:

- Legacy and `2026-07-28` matrices are visible and independently gated.

### 7.4 HTTP authorization/security

Tasks:

- Remote discovery defaults to no tool calls.
- Header/bearer auth via secret references.
- Local fake OAuth/OIDC issuer for PKCE, metadata discovery, client
  credentials, token refresh, audience, and scope tests.
- Origin/DNS-rebinding, redirect, header mismatch/injection, token leakage, and
  session tests.
- Live mutating calls require explicit profile and disposable account.

Acceptance:

- The official feature reference server reaches a meaningful authenticated
  inventory path.
- Secrets never appear in normal logs/reports.

## 8. Phase 5 — schema-aware dynamic MCP testing

Priority P1/P2, size L.

### 8.1 Valid input generation

Tasks:

- Generate valid objects for all required schema types and nested structures.
- Mutate one field per adversarial case while preserving overall validity.
- Support examples/defaults/formats/unions/enums/bounds and custom fixtures.
- Identify unsatisfiable or unsupported schemas explicitly.

Acceptance:

- Memory's array/object-based tools receive valid benign calls.
- Invalid input rejection is not misclassified as a security finding.

### 8.2 Controlled services and egress

Tasks:

- Dedicated internal Docker network with DNS, HTTP(S), TCP, and cloud-metadata
  emulators.
- Default-deny gateway with destination/byte accounting.
- Synthetic API keys, credentials, files, and canary tokens.
- Service fixtures for common databases and SaaS-shaped APIs.

Acceptance:

- API-backed tools can be exercised without the public internet or real
  credentials.
- A canary exfiltration produces deterministic evidence.

### 8.3 Scenario isolation and side effects

Tasks:

- Classify read-only, reversible, mutating, destructive, and external actions.
- Fresh state per mutating scenario.
- Explicit cleanup oracle.
- Global/per-tool budgets and concurrency limits.

Acceptance:

- No scenario can mutate a user's real account under default settings.

## 9. Phase 6 — realistic Skills and prompt testing

Priority P1/P2, size L.

### 9.1 Skill invocation manifests

Tasks:

- Define `detonate.scenarios.yaml` for script command, args, stdin, cwd,
  fixtures, dependencies, expected exit, and cleanup.
- Infer scenarios only from unambiguous documented examples.
- Validate filesystem artifacts against the Agent Skills specification; make
  malformed frontmatter a validation result rather than silently discarding it.
- Distinguish declared entry scripts from helper libraries. Any script/file
  discovery cap sets an explicit truncation flag and partial completeness.
- Install/build skill dependencies through the safe acquisition pipeline.
- Capture stdout, stderr, exit, files, processes, and network per invocation.
- Add Python, shell, JS, TS, and executable support via runtime profiles.

Acceptance:

- Anthropic PDF/DOCX skills run at least one valid documented workflow rather
  than invoking every helper with zero arguments.
- Missing invocation data yields partial coverage.
- Malformed metadata and scan truncation are visible in JSON/text/SARIF.

### 9.2 Progressive disclosure

Tasks:

- Model skill content exposure as a graph.
- Record which referenced files/assets are loaded by stage.
- Add hidden-instruction, cross-file override, path escape, and poisoned asset
  cases.

### 9.3 Prompt suites

Tasks:

- Versioned benign/malicious prompt corpus.
- Template-variable and multi-turn cases.
- Deterministic signatures plus optional LLM behavior trials.

Acceptance:

- Prompt reports distinguish static findings from model-dependent behavior.

### 9.4 Experimental Skills over MCP

Tasks:

- Feature-flag `skills/list`, `skills/get`, and backing `resources/read`.
- Verify per-file digests and origin namespaces; bound pagination, nesting,
  resource bytes, and file count.
- Add the working-group threat-model corpus: cross-server reads, URI/path
  escape, TOCTOU/content rotation, oversized/endless responses, name
  impersonation, nested-skill consent, hidden instructions, and
  `allowed-tools` privilege widening.
- Never execute a fetched skill or widen permissions without an explicit
  scenario and host approval.

Acceptance:

- Experimental support is absent from default compatibility claims.
- A server cannot rotate skill content after approval or use one origin to read
  another origin's files without a deterministic finding/failure.

## 10. Phase 7 — optional LLM/agentic harness

Priority P2/P3, size L.

### 10.1 Record/replay first

Tasks:

- Provider-neutral request/response/tool-call types.
- Transcript redaction, hashing, and encrypted opt-in bundles.
- Replay provider for zero-cost deterministic CI.
- Budget, token, latency, and cost accounting.

### 10.2 Ollama adapter

Tasks:

- Native `/api/chat` adapter with tool calls and structured output.
- Optional OpenAI-compatible path.
- Capability probe because support varies by local model.
- Model-not-installed remediation; never auto-pull multi-GB models without
  consent.

Acceptance:

- A local model can select an MCP tool, receive a synthetic result, and finish
  an agent loop while all actions remain in the sandbox.

### 10.3 Hosted adapters

Order:

1. OpenAI Responses API.
2. Anthropic Messages API.
3. Gemini Interactions API.

Tasks:

- Environment/secret-store key references.
- Route provider traffic through the trusted control plane; target containers
  never receive provider credentials or provider-network access.
- Data-egress preview and explicit consent.
- Strict tool schemas where supported.
- Provider/model capability snapshot and retry/rate-limit handling.
- No automatic provider fallback, because switching models changes the
  experiment.

### 10.4 Statistical evaluation

Tasks:

- Repeat trials across fixed cases.
- Measure malicious tool-selection, canary leakage, approval bypass, schema
  adherence, and task success rates.
- Report confidence intervals and raw trial counts.
- Keep LLM results out of deterministic CI verdicts unless a project explicitly
  defines a statistical gate.

## 11. Phase 8 — installation, release, and supply chain

Priority P1 for basic release, P2 for ecosystem channels, size M.

### 11.1 Release engineering

- Cross-compile supported OS/architectures from a clean checkout.
- Generate checksums, signatures, SLSA provenance, and SPDX/CycloneDX SBOM.
- Pin action SHAs and least-privilege workflow permissions.
- Publish only from an annotated, protected tag after CI.
- Do not move or reuse the previously pushed `v0.1.0` identity; publish a new
  version only after all first-release gates pass.
- Verify each archive by installing and running `detonate doctor` plus a smoke
  scan.

### 11.2 Installation channels

Order:

1. GitHub release archives.
2. `go install`.
3. Homebrew tap.
4. Scoop and/or winget.
5. Optional signed container image for CI.

Avoid requiring Go for normal users. Avoid an unauthenticated `curl | sh`
installer as the primary path.

### 11.3 First-run experience

`detonate doctor` checks:

- Docker/backend installed and running.
- Rootless/VM boundary status.
- CPU architecture, disk/memory budget, network/proxy.
- Required image availability/digests.
- Optional Ollama endpoint/model and hosted-provider config.
- A tiny sandbox self-test and verified cleanup.

The first scan prints stage/coverage estimates and never downloads large images
or models without clear consent.

## 12. Phase 9 — stronger isolation and observability

Priority P3, size L.

- Rootless Docker/Podman backend.
- gVisor and Kata profiles.
- Firecracker worker for hosted/high-risk scans.
- Optional Linux eBPF/Fanotify sensor.
- Backend equivalence tests and explicit report boundary.

Do this after correctness and compatibility. Strong isolation does not repair a
false-positive detector or a skipped scenario.

## 13. Compatibility corpus

The permanent corpus should test shapes, not popularity:

| Target | Shape/coverage goal |
|---|---|
| First-party Go fault-injection server | Deterministic `2026-07-28` and legacy modes over stdio/HTTP, malformed frames, pagination, crashes, delays, MRTR, subscriptions |
| MCP Everything | Full legacy/current protocol surface: tools, prompts, resources, progress, extensions |
| MCP Memory | Nested array/object schemas and persistent writable state |
| MCP Filesystem | Allowed roots, path traversal, mutations, symlinks, synthetic files |
| MCP Fetch | Python packaging and controlled HTTP |
| MCP Git | Python plus required system binary |
| MCP Time | Python packaging and pure tools |
| GitHub MCP server | Go build, large tool set, auth without live mutations |
| Playwright MCP | Browser image, large dependencies, process tree, downloads |
| Kubernetes MCP server | Go/system profile, auth/config isolation |
| MCP Toolbox for Databases | Go binary plus disposable database emulator |
| Official feature reference server | Streamable HTTP, modern protocol, OAuth, all primitives |
| Public Gemini weather demo | Optional nightly remote HTTP/downgrade smoke; never a required PR gate |
| Anthropic PDF/DOCX skills | Nested scripts, dependencies, realistic file fixtures |
| Benign/malicious prompt corpus | Static and agentic precision/recall |

Every row records immutable version, expected supported features, required
fixtures, and known expected failures.

## 14. CI layout

Fast pull-request lane:

- Format, vet, static analysis, unit tests, report golden tests.
- Clean-checkout CLI build.
- Non-Docker protocol fixtures.

Docker pull-request lane:

- Sandbox policy/escape tests.
- Acquisition fixtures with local registries.
- Reference server/skill smoke corpus.
- Race detector.

Nightly lane:

- Current MCP conformance matrix.
- Full compatibility corpus and image architectures.
- Static calibration corpus.
- Optional local-model agentic replay/live subset.

Release lane:

- All required lanes green.
- Reproducible build, signing, SBOM/provenance.
- Fresh-machine install and smoke test.

## 15. Recommended immediate sequence

Work in this order:

1. Fix and track the executable entrypoint; add clean-checkout CI.
2. Fix the `ENOTFOUND`/`ModuleNotFoundError` false positive and script exit
   accounting.
3. Implement risk plus completeness and stop unqualified clean results.
4. Bound outputs, wire Docker events, collapse crash cascades, and add
   provenance.
5. Split fetch from offline build.
6. Repair/version the compatibility harness and run the core corpus.
7. Add Go/runtime profiles.
8. Introduce MCP protocol/transport interfaces and official conformance.
9. Add schema-aware probing and controlled service emulators.
10. Add realistic skill scenarios.
11. Add Ollama record/replay, then hosted providers.
12. Implement the Phase 8 release controls needed for signing, SBOM/provenance,
    archive verification, and fresh-machine install tests.
13. Cut the first public release only after Phases 0–2, those Phase 8 release
    gates, and a documented compatibility baseline pass. If networked
    target-code build/install is not yet isolated, disable it by default and
    ship only profiles that can honestly report complete coverage.

This order produces a smaller but honest release before a broader scanner that
can silently skip or misclassify targets.

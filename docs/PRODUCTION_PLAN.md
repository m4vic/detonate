# Detonate production plan

Status: active. Last verified against the local repository on 2026-08-13.

This is the execution plan for making Detonate safe enough to promote beyond
an experimental local CLI. It complements, rather than replaces,
[ROADMAP.md](ROADMAP.md), [TASKS.md](TASKS.md),
[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md), and
[ARCHITECTURE.md](ARCHITECTURE.md).

## Scope and production bar

Detonate is a local, stateless security CLI. It is not a hosted service, so
uptime, backup/restore, and paging SLOs do not apply directly. Its production
bar is instead:

1. It never executes target-controlled code on the host or with both root and
   network access.
2. Every requested scan ends in a truthful, structured outcome; timeout,
   cancellation, crash, and cleanup failure must never look clean.
3. A finding is deterministic, evidence-backed, and distinguishable from
   incomplete coverage.
4. The released artifact and the claims made about it are reproducible.

The repository invariants in [ROADMAP.md](ROADMAP.md) remain non-negotiable:
no LLM verdicts, separate risk and completeness, no host execution, no
network in the detonation sandbox, no telemetry, and evidence for every
finding.

## Evidence-based starting point

The local Git history contains `v0.1.0` and `v0.2.0`. `v0.2.0` points to
`5febd98` (2026-08-07), a documentation-only commit; the first canary code
landed later in `511f607`. Therefore the tag must not be treated as proof that
the v0.2 canary gates shipped.

What exists today:

- Static analysis and a Docker-backed dynamic MCP/skill path.
- A sandbox policy that disables network access, uses a read-only rootfs,
  drops capabilities, runs as non-root, and applies memory/PID limits.
- Structured text, JSON, and SARIF reporting; independent risk and
  completeness assessment; and scenario outcomes.
- An isolated `GenerateCanary` staging helper and a preliminary
  `NetworkProxy` policy field; neither is wired into all scan surfaces yet.
- Daemon-side sandbox cleanup code that attempts and verifies container
  removal.
- Two-phase dependency acquisition: an inert, networked fetch followed by
  network-disabled, non-root installation/build. Unsafe manifest forms and
  network-dependent hooks are reported as `acquisition_unsupported`.
- Scanner-owned canary staging that never writes into the target tree and has
  explicit, idempotent cleanup.
- Structured teardown failures that force failed completeness and a non-zero
  exit after an otherwise completed MCP scan.

What is still open:

- Budgets are not consistently modeled or reported across acquisition,
  startup, protocol calls, output, and disk.
- Canaries are not yet seeded at the four required surfaces, matched through
  common encodings, or connected to finding and coverage semantics.
- There is no reproducible precision/recall run over a pinned corpus.
- The release workflow now has a `verify` job that must pass before GoReleaser
  runs. Its tag-triggered behavior still needs evidence from a real release;
  the pre-tag checklist requires a snapshot run first. It produces checksums
  only; SBOM, provenance attestation, and signing remain unimplemented.

## Risks and required controls

| Priority | Risk | Required control | Acceptance evidence |
|---|---|---|---|
| P0 | A dependency hook reaches the network as root before detonation. | Split acquisition into fetch-without-execution and offline, non-root build. Unsupported networked builds reduce completeness explicitly. | A malicious `postinstall` fixture cannot egress; policy tests prove no path combines target execution, root, and network. |
| P0 | A hostile target hangs, crashes the harness, fills output, or survives cleanup. | Define total, phase, call, output, and disk budgets; propagate cancellation; treat cleanup as a reportable terminal phase. | Fault injection for each phase returns a structured non-clean result and leaves no `detonate-*` container or dependency volume. |
| P0 | A clean report is issued after an incomplete or unverifiable scan. | Preserve terminal scenario outcomes and make teardown/cleanup errors affect the result and exit code. | Table-driven tests show cancellation, timeout, target crash, acquisition failure, harness failure, and teardown failure never return exit `0`. |
| P1 | Canary evidence is non-deterministic, incomplete, or mutates the scanned artifact. | Specify per-scan canary lifecycle, isolated staging, encoding-aware matching, evidence shape, and nonce-free fingerprints. | Positive/negative fixtures for environment, file, tool-input, and network-intent canaries; identical SARIF fingerprints across two scans. |
| P1 | Capability claims lack calibration. | Pin a corpus and publish a versioned scoring method for recall and precision. | One documented command produces both measures; CI detects regressions. |
| P1 | A release label overstates what shipped. | Release only from a completed task section, with the evidence recorded on the same change. | Release checklist links tag, commit, passing checks, and completed milestone gates. |
| P1 | A release can be published without the test evidence or supply-chain record that makes it trustworthy. | Make release promotion depend on the verified CI gates and generate checksums, SBOM, provenance, and a signature/verification path. | A dry-run release and a rollback exercise prove the released artifact can be verified and a bad publication can be withdrawn or superseded. |

## Delivery sequence

### Phase 0 — establish the contracts

Progress as of 2026-08-12:

- [x] Scanner-created canary files use isolated, scanner-owned staging rather
  than mutating the target directory; cleanup is explicit and error-returning.
- [x] MCP sandbox and dependency-volume cleanup errors after a completed scan
  become a `pipeline.teardown` scenario and structured `teardown_failed`
  failure, forcing completeness to `failed` and a non-zero exit.
- [x] Freeze and test the two-phase acquisition boundary: networked fetch is
  script-disabled/wheel-only; all target-controlled install and build work is
  offline and non-root.
- [ ] Add the remaining cancellation, timeout, output, disk, and phase-budget
  contracts.

The landed contract tests now anchor these safety rules; remaining Phase 2
tests must extend them without weakening them:

- Acquisition policy: no target-controlled instruction may run as root with
  network access.
- Lifecycle policy: all containers and dependency volumes are gone before a
  clean report is emitted.
- Outcome policy: every requested scenario has a terminal result; failed
  cleanup is not ignored.
- Canary policy: instrumentation is isolated from the source artifact,
  short-lived, and cannot make finding fingerprints unstable.

Document the failure taxonomy and exit-code mapping in the report contract.
This is the minimum needed to prevent an implementation from accidentally
passing its own incomplete definition of safety.

### Phase 1 — safe acquisition (implemented; release review pending)

The current worktree implements two-phase acquisition:

1. Fetch dependencies with network enabled but lifecycle scripts disabled
   (`npm ci --ignore-scripts`; `pip download` or equivalent wheel-cache flow).
2. Build/install from that cache in a network-disabled, non-root container.
3. Emit `acquisition_unsupported` with reduced completeness when a target
   needs a networked build hook; never silently relax the policy.

Registry-backed Node projects and wheel-only Python requirements are supported.
Local Python project builds, source distributions, recursive requirements,
VCS/local Node dependencies, and hooks that require network access are
explicitly unsupported rather than run across the safety boundary.

Acceptance evidence recorded on 2026-08-12:

- `TestAcquisitionPoliciesNeverCombineTargetExecutionRootAndNetwork` proves
  the policy/command pairing.
- `TestLifecycleHookRunsOfflineNonRootAndEgressIsReported` runs a hostile npm
  `postinstall` in Docker, proves it is non-root, and records its blocked DNS
  attempt as critical acquisition evidence.
- Docker-backed Python import and TypeScript compilation tests prove fetched
  dependencies and build output work in the offline detonation path.
- Manifest-validation tests cover Python source forms plus modern and legacy
  npm lockfiles; unsupported Python project acquisition is preserved in the
  scan report.
- Repository-derived monorepo paths are passed as shell arguments rather than
  interpolated into the root/networked fetch script; a metacharacter fixture
  guards the command boundary.
- A failed offline hook retains its blocked-egress events on the structured
  unsupported report, so exiting non-zero cannot erase security evidence.
- `go test -count=1 -timeout 20m ./...` and `go vet ./...` pass locally.

This closes the implementation portion of the acquisition gate. Maintainer
review, CI evidence, and release bookkeeping remain before it is a shipped
claim.

### Phase 2 — lifecycle truthfulness

Make all resource and failure paths first-class scan results:

- Introduce explicit, configurable budgets for total scan time, acquisition,
  startup, tool calls, output/evidence, and disk use.
- Report truncation and the budget that caused it.
- Extend the landed `Close`/volume-cleanup failure coverage to cancellation
  and partial-start paths.
- Test Ctrl-C, deadline expiry, non-responsive targets, malformed protocol
  output, Docker failures, and cleanup failures.
- Add an end-of-run orphan check in the Docker integration suite.

This phase may be delivered with Phase 1 if the acceptance tests remain
separable. It must be complete before calling a release safe for CI gating.

### Phase 3 — canary-backed evidence

Build canaries on the Phase 0 contract, not around the current helper:

- Environment secrets, plausible-file secrets, tool-input markers, and
  network-intent markers each receive positive and negative fixtures.
- Use an isolated temporary mount/volume, not the user target directory, for
  scanner-created files. Cleanup is verified and failure is surfaced.
- Match plaintext, base64, hex, and URL encodings while retaining the exact
  evidence necessary to explain the finding.
- Provide a network-intent sinkhole on an internal Docker network with no
  gateway; prove it cannot route to the Internet.
- Exclude volatile nonce data from stable finding fingerprints.

An untouched canary receives neither a finding nor coverage credit. A canary
is evidence of an observed flow, not proof that an untested surface is safe.

### Phase 4 — measurement and release evidence

After canary behavior is fixed, vendor or pin the chosen MCPTox corpus and
define scoring before publishing any number. The methodology must specify the
corpus revision, target setup, timeout/budget policy, recall denominator,
false-positive corpus, and how unsupported/incomplete cases are counted.

Add a single reproducible benchmark command and CI regression thresholds.
Publish precision and recall together, with the date and corpus revision.
Release evidence must also include clean-archive builds for supported
platforms, checksums, a fresh-install smoke test, SBOM, provenance attestation,
and a documented verification command. Make the release workflow depend on
the same checks rather than trusting that a tag was created after they passed.
Exercise the rollback/withdrawal procedure once before relying on it.

Write a short release-and-incident runbook covering: an unsafe acquisition
finding, an orphaned container/volume, an incorrect clean verdict, and a bad
published release. For this local CLI, stable error codes, structured reports,
`doctor`, and this runbook are the operational signal; an uptime dashboard or
pager is not required.

## Release and roadmap reconciliation

The release ladder currently names canaries as v0.2, safe acquisition as
v0.3, and measurement as v0.4, while the v0.2 tag was cut before the canary
milestone. Do not relabel an existing tag. Before the next release, choose and
record one of these approaches:

- Keep the existing tags as historical artifacts and ship the safety boundary
  as the next earned release, then bundle canaries and measurement into the
  following earned release; or
- Renumber future roadmap sections without changing published tags.

Either approach is valid; the invariant is that a release tag, CHANGELOG, and
the completed checklist describe the same delivered scope. This decision is a
maintainer/release-policy choice and should be made before publishing the next
tag.

## Explicitly deferred

Streamable HTTP, authorization flows, full MCP primitive coverage, eBPF
tracing, registry-scale scanning, and the 1.0 schema/flag freeze remain in the
roadmap. They are not prerequisites for the safety-and-measurement milestone
above, unless a supported-user commitment requires them.

## Completion checklist

The plan is complete when all of the following are demonstrated, not merely
implemented:

- The acquisition egress fixture is blocked and reported.
- No cleanup, cancellation, timeout, crash, or harness fault can yield exit
  `0` or omit a structured outcome.
- Dynamic integration runs leave no Detonate containers or dependency volumes.
- All four canary classes pass positive and negative fixtures, and fingerprints
  are stable across scans.
- A pinned corpus produces reproducible precision and recall results.
- A release dry run proves the artifact can be verified and that release
  promotion is blocked when its prerequisite checks are absent.
- The release checklist, CHANGELOG, roadmap/task status, and tag agree.

## Ownership and operating notes

Security-sensitive changes require a second review by a maintainer who did
not author the change, especially acquisition policy, sandbox policy, report
outcomes, and benchmark scoring. The review responsibility belongs to people
and repository policy; this document intentionally does not assign it to a
particular AI tool.

Docker is required to execute and verify the dynamic gates. Static mode can
still run without Docker, but it cannot establish the safety claims in this
plan.

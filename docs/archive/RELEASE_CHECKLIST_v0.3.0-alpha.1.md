# Release checklist — v0.3.0-alpha.1

Status: closed 2026-08-13 (released); reconciled 2026-08-20. This is a **release punch-list, not a build plan** — the design is
settled; these are the specific things that must pass before the tag. Derived from a Codex audit,
each claim re-verified against the code by Claude (the two saved-report items were found to share
one root cause; see item 1).

## Scope discipline

**This alpha contains ONLY the fixes below.** No new features. Developer architecture analysis,
the OpenAI integration, and anything in `DEVELOPER_ANALYSIS_LLM_PLAN.md` stay in the **next**
milestone (v0.4 "measured"). Scope creep is what has kept this at "almost releasable" — the
discipline is to ship the tight thing.

## Owner split (worker vs verifier)

- **Claude** owns the invariant-critical fixes — where a wrong fix silently *looks* right.
- **Codex** owns mechanical breadth — high-throughput, verified green by the acceptance check.
- **Claude verifies the whole** before the tag is cut.

## Must-fix (blocking the tag)

- [x] **1. Saved-report replay reuses the live path's safety — exit code AND sanitization.**
      **Owner: Claude. Done 2026-08-12, verified.** Root cause was one architectural gap:
      `runSavedReport` → `bundle.Text` bypassed both the live path's semantic-exit computation and
      its per-field sanitization. Fixed by (a) new shared leaf `internal/termsafe` — one `Clean`
      used by both the live renderer (`cli.terminalSafe` now delegates) and `bundle.Text` (each
      target-controlled field cleaned per-field); (b) new `App.exitForScan` — one semantic-exit
      helper called by both `reportMachine` and `runSavedReport`, so replay can't exit 0 on a
      report with findings.
      — *verified:* `go build`/`go vet` clean; `TestTerminalSafeRemovesTargetControlledEscapeSequences`
      passes (sanitizer); `TestStaticSaveBundleAndOfflineRerender` updated to assert the hostile
      bundle replays as `exitFindings` (3), not 0 — the regression guard Codex asked for. Full
      `cli`+`bundle`+`termsafe` suite green.

- [x] **2. Release workflow gated on CI; CHANGELOG claim made true.**
      **Owner: Claude. Done 2026-08-12; CI-gating not yet exercised on GitHub.** Added a `verify`
      job to [release.yml](../../.github/workflows/release.yml) (tracked-entrypoint, gofmt, vet,
      `-race` test, docker) that `goreleaser` now `needs:`. This makes the CHANGELOG's "release
      publication depends on … gates" line accurate rather than false.
      — *verified locally:* YAML parses; gates mirror `ci.yml`. **Not yet verified:** that a tag
      with a failing test actually blocks publish — that requires a real tag push + Actions run,
      so it stays *written-but-unproven-in-CI* until then (groundtruth: not claiming it works
      until it's run).

- [x] **3. gofmt + go mod tidy clean.** **Owner: Codex.** `gofmt -l` currently flags
      `internal/cli/interactive_test.go`, `internal/mcpdriver/session.go`,
      `internal/probe/engine.go`; `go mod tidy -diff` shows `readline` should be direct and
      `go.sum` is incomplete. Also: GoReleaser runs `go mod tidy` during packaging — remove that so
      release can't silently mutate deps.
      — *check:* `gofmt -l .` empty; `go mod tidy -diff` empty; CI verifies both.
      — *verified 2026-08-13 (Codex):* formatted the three named files, tidied
      module metadata, removed GoReleaser's tidy hook, and both clean checks pass.

- [x] **4. Exclude `detonate.exe~`.** **Owner: Codex.** The `*.exe` ignore misses the `~` suffix; a
      ~10 MB binary is currently untracked-and-stageable.
      — *check:* `git status` no longer lists `detonate.exe~`.
      — *verified 2026-08-13 (Codex):* `*.exe~` now ignores the backup and
      `git status --short` no longer lists it.

## Should-fix (reproducible evidence — the "reproducible" production bar)

- [x] **5. Pin sandbox image digests + record target provenance in the bundle.**
      **Owner: Codex; Claude reviews the evidence shape.** Images are mutable tags
      (`python:3.12-slim`, `node:22-slim`) in [detect.go:468](../../internal/acquire/detect.go). For
      `repo --path examples/hello-world-node`, the saved target is only the repo URL, so different
      monorepo packages produce ambiguous bundles. Record: repo URL, requested subpath, resolved
      commit SHA, detonate version/commit, sandbox image **digest**.
      — *check:* two scans of the same monorepo subpath produce distinct, unambiguous bundle
      identities; image references are `@sha256:…`.
      — *verified 2026-08-13 (Codex):* real MCPB scans of
      `examples/hello-world-node` and `examples/file-system-node` saved distinct
      identities at target commit `70fe3b34…`; both manifests record the exact
      dirty Detonate build and pinned Node image digest.

## Doc truthfulness (the same drift that produced the fake v0.2.0 tag)

- [x] **6. Reconcile docs with what actually shipped.** **Owner: Codex.**
      - README says Docker is required for everything except prompts — scriptless skill analysis now
        works without it.
      - SECURITY.md describes the old Docker/acquisition boundaries.
      - CHANGELOG omits saved bundles, colors, safe acquisition, cleanup handling, Node handoff.
      - COMPATIBILITY.md is dated Jul 30 with obsolete claims — add the successful MCPB run and the
      current "Everything" acquisition failure.
      — *check:* a fresh read of each doc matches current behavior; no contradictions.
      — *verified 2026-08-13 (Codex):* README, SECURITY, CHANGELOG, COMPATIBILITY,
      and TASKS now match the two-phase boundary, Docker-free scriptless skill
      analysis, saved provenance, UI/cleanup/Node changes, MCPB success, and the
      current named Everything limitation.

## Compatibility honesty (fix or document, don't hide)

- [x] The official MCP "Everything" target fails acquisition (expects `dist/`) — contradicts the
      "monorepo support" task marked done in [TASKS.md](TASKS.md). Either fix, or reopen the task and
      report a named unsupported reason. **Owner: Codex; Claude judges which.**
      — *verified 2026-08-13 (Codex):* real target commit `76d64c82…` now reports
      `acquire/acquisition_unsupported` with the root-lockfile/workspace-prepare
      reason; the monorepo compatibility task was reopened.
- [x] A zero-argument MCP tool is announced as "probed with 13 payloads" then marked unsupported —
      overstates coverage. Say "no adversarial string-input surface" instead. **Owner: Codex.**
      — *verified 2026-08-13 (Codex):* a real MCPB hello-world probe run stated
      that one tool had no adversarial string-input surface and sent no payloads.
- [x] MCP servers that build but exit on missing config should retain bounded stderr + an actionable
      config hint. **Owner: Codex.**
      — *verified 2026-08-13 (Codex):* Docker integration regression preserves
      `missing DATABASE_URL` and adds the env/credentials/arguments/config and
      stdio-MCP hint.
- [x] `doctor` should be the obvious preflight for dynamic scanning. **Owner: Codex.**
      — *verified 2026-08-13 (Codex):* dynamic mode prints the preflight command,
      runtime-unavailable errors point to it, and a real `doctor` run diagnosed
      then confirmed Docker Desktop readiness.

## Pre-tag verification gate (Claude runs this, on real Docker)

- [x] All must-fix (1–4) pass their checks. **Verified 2026-08-13 (Codex):**
      `gofmt -l .`, `go mod tidy -diff`, `go vet ./...`, and the full Windows
      Docker-backed race suite passed; `detonate.exe~` is ignored.
- [x] One pinned public MCPB smoke run completes (acquisition → sandbox → handshake → inventory).
      **Verified 2026-08-13 (Codex):** `mcpb#examples/hello-world-node` at
      `70fe3b34…` completed all four phases and saved a provenance bundle.
- [x] Zero `detonate-*` containers or dependency volumes remain afterward.
      **Verified 2026-08-13 (Codex):** Docker audit immediately after the MCPB
      smoke found zero containers and zero volumes with that prefix.
- [x] GoReleaser **snapshot** (dry run) succeeds. **Verified 2026-08-13
      (Codex):** GoReleaser v2.17.1 validated the configuration and built six
      Linux, macOS, and Windows archives plus checksums as `0.3.0-next`.
- [x] `git fetch` — reconcile with `origin/main`. **Done 2026-08-13** (merged as PR #3);
      the local clone was re-synced 2026-08-20, which also corrected a divergent local
      `v0.1.0` tag that pointed at `4ae5fd4` instead of the published `5c5aa38`.
- [x] Only then: tag `v0.3.0-alpha.1`. **Done 2026-08-13.** Annotated tag on `58f3517`,
      pushed; GitHub release published and marked Latest at 11:58Z.

## Outcome

**Released 2026-08-13.** Both workflow runs on the tag completed successfully — `Release`
(3m05s) and `CI` (1m27s) — which retires the item-2 caveat: the release gate is no longer
"written-but-unproven-in-CI" on the passing path. It has still never been observed
*blocking* a bad tag; proving that needs a deliberately failing tag, and nobody should cut
one to find out. Treat it as verified-green, unverified-red.

One gap this checklist did not catch, found on 2026-08-20 and now fixed: the suite's 21
Docker-backed tests skip silently when no daemon is present, so "tests passed" in the
pre-tag gate did not by itself mean the sandbox invariants were exercised. CI now sets
`DETONATE_REQUIRE_DOCKER=1`, which turns those skips into failures. See
[PLAN_v0.4.0-static-detection.md](PLAN_v0.4.0-static-detection.md) §3.

Next milestone: [PLAN_v0.4.0-static-detection.md](PLAN_v0.4.0-static-detection.md).

## Explicitly OUT of scope for this alpha

Developer architecture analysis · OpenAI integration · `/full`, `/model` · SBOM/provenance/signing
(v0.4+) · transport breadth (v0.9) · the v1.0 contract freeze. These stay in
[ROADMAP.md](ROADMAP.md) / [PRODUCTION_PLAN.md](PRODUCTION_PLAN.md).

# Work plan — v0.4.0 "Static mode worth running"

Status: **superseded 2026-08-20 by [PLAN.md](../PLAN.md).** Kept as the record of
what Phase 0 and Phase 1 actually delivered; do not plan from it.

The strategy changed after this document was written. Market evidence showed the
measured problem in this space is a ~78% false-positive rate across existing
scanners, which reprioritized calibration and canary instrumentation ahead of the
remaining items here. What this plan got right — static detection first, because
the benchmark measures a detector that did not exist — still stands and is done.

This is a **build plan**, not a release punch-list. The v0.3.0-alpha.1 checklist
was the latter and is now closed. Each task below states its acceptance check;
a task is done when the check passes, not when the code exists.

## 1. Why this is v0.4 and not the benchmark

ROADMAP.md schedules v0.4 as **Measured** — run MCPTox, publish recall and
precision. An audit of the tree on 2026-08-20 found that milestone is blocked by
work scheduled three versions later, for two reasons that are facts about the
code rather than opinions about priority:

**MCPTox measures a detector that does not exist.** MCPTox is a tool-poisoning
corpus: poisoned tool names, descriptions, and schemas. Detonate collects tool
descriptions into `toolinfo.ToolInfo` in all three driver paths, and
[toolinfo.go:7](../../internal/toolinfo/toolinfo.go) comments that the description
is "the thing an attacker poisons" — but no rule ever reads it. Current
detection is 13 adversarial payloads injected into string parameters
(`internal/probe`) plus regex signatures over *skill instructions*
(`internal/skill/analyze.go`). Neither analyzes MCP tool metadata. Running the
benchmark today publishes a number near zero, and it would be measuring absence,
not performance.

**Neither corpus is vendored.** No MCPTox in the tree, and the 59-skill and
40-Google-skill false-positive corpora that ROADMAP.md describes as "existing"
are not in the repository either — those were ad-hoc runs. The v0.4 gate
"corpus is versioned and immutable" starts from zero twice.

Building the static detector first inverts both problems: it is the thing MCPTox
scores, and it is also the fix for the empty front door
([mode.go:238](../../internal/cli/mode.go) hard-codes `OutcomeUnsupported` with the
reason "MCP static source analysis is not implemented" — the no-Docker path
every new user hits first). It needs no Docker, so it is deterministic, fast,
and fully CI-testable, unlike the 21 Docker-gated tests that silently skip.

**Resulting ladder** — themes swap, relative order of everything else is kept:

| Version | Theme | Was |
|---|---|---|
| **v0.4.0** | Static mode worth running | v0.7 |
| v0.5.0 | Measured | v0.4 |
| v0.6.0 | Findings you cannot argue with (canary) | v0.2, never shipped |
| v0.7.0 | Declared versus observed | v0.5 |
| v0.8.0 | Targeted probing | v0.6 |

v0.8 "Budgets and lifecycle" and beyond are unchanged. The canary milestone is
re-slotted rather than dropped: `probe.GenerateCanary` exists but is called by
nothing except its own test, so v0.2 was never delivered and its position in the
ladder is free.

## 2. Open decisions — yours, not the plan's

The plan assumes both answers below. If either is wrong, say so before Phase 1
starts; Phase 0 is safe either way.

- **Assumed: no external deadline on publishing a number.** If a post, launch,
  or commitment is already scheduled, the ordering argument weakens and Phase 2
  may need to run first against a reduced claim.
- **Assumed: v0.5's number is a README line plus a reproducible command**, not a
  traffic-driving writeup. The second raises the corpus bar considerably.

## 3. Phase 0 — Hygiene (one evening)

Small, reversible, unblocks trustworthy local verification. No design decisions.

- [x] **P0/S** Add `.gitattributes` normalizing line endings.
      Root cause of a standing false alarm: `core.autocrlf=true` with no
      `.gitattributes` means `gofmt -l .` flags ~14 files and `go mod tidy -diff`
      reports `go.sum` drift on Windows, while CI on Linux is clean. Every local
      pre-tag check currently lies.
      — *check:* on Windows, `gofmt -l .` is empty and `go mod tidy -diff` is
      empty, with no source edits beyond the normalization commit.

- [x] **P0/S** Unit-test `internal/termsafe` directly. **Done 2026-08-20.**
      The shared sanitizer both renderers depend on has no test file of its own;
      it is covered only indirectly through `cli` and `bundle`. It is the one
      leaf where a silent regression reaches both output paths at once.
      — *check:* `go test ./internal/termsafe` covers ANSI/CSI/OSC sequences,
      bare control runes, invalid UTF-8, and the newline-stripping contract that
      is the reason `bundle.Text` cleans per-field instead of wrapping the blob.

- [x] **P0/S** `git fetch` — reconcile the local clone. **Done 2026-08-20.**
      `origin/main` was stale at `58f3517`; it is now `2a26fd0`, three commits
      ahead of the local release branch (the PR #3 merge plus two README edits
      pushed the evening of 2026-08-13).

- [~] **P1/S** Fast-forward local `main` and decide the release branch's fate.
      **Partly done 2026-08-20.** `main` was at `ff9b4b1` (2026-08-08) and is now
      `2a26fd0`, matching `origin/main`; fast-forwarded via `git fetch origin
      main:main` so the working tree was never disturbed. **Still open:**
      `release/v0.3.0-alpha.1` is merged and tagged but remains the checked-out
      branch, so it cannot be retired from where we are standing. Retire it when
      the next piece of work starts from `main`.
      — *check:* `main` matches `origin/main`; no stale local branch claims to
      be a release candidate.

- [x] **P1/S** Fix the divergent local `v0.1.0` tag. **Done 2026-08-20.**
      Local `v0.1.0` points at `4ae5fd4`; the published tag is `5c5aa38`. Fetch
      rejects it as "would clobber existing tag", so `git describe` and any
      local build stamped from it disagree with the release.
      — *check:* `git rev-parse v0.1.0` matches the remote; `git fetch --tags`
      is clean.

- [x] **P1/S** Make Docker-gated skips loud in CI. **Done 2026-08-20.**
      21 tests — every sandbox invariant, including `TestSandboxBlocksNetwork`,
      `TestSandboxDoesNotRunAsRoot`, `TestSandboxIsRemovedAfterClose`, and
      `TestMonitorCatchesExfiltrationAttempt` — skip silently when Docker is
      absent. A full local run reports green with none of the security
      invariants exercised. Skipping is right for a laptop; silent skipping is
      wrong for CI.
      — *check:* with `DETONATE_REQUIRE_DOCKER=1`, a missing daemon fails the
      run instead of skipping; the Docker CI lane sets it.

- [x] **P2/S** Close out the v0.3.0-alpha.1 checklist. **Done 2026-08-20.**
      Its last two boxes (reconcile with `origin/main`, cut the tag) are untrue
      on paper — the tag shipped on 2026-08-13 and both workflow runs passed.
      — *check:* the checklist states what actually happened, including that the
      release gate has now been exercised green on a real tag push.

## 4. Phase 1 — Static poisoning detection (the milestone)

New leaf package `internal/toolscan`: deterministic rules over MCP tool
metadata. Placed as a leaf for the same reason `termsafe` is one — static mode
and dynamic mode must reach identical verdicts on identical inventory, and two
copies would drift.

- [x] **P0/M** Rule engine over `toolinfo.ToolInfo`. **Done 2026-08-20.** — name, description, input
      schema, annotations, and metadata. Pure function, no I/O, no network, no
      model.
      — *check:* the same `[]ToolInfo` yields byte-identical events across runs
      and across static and dynamic mode.

- [x] **P0/M** Rule set, each with a positive and a negative fixture. **Done 2026-08-20.**
      instruction-injection phrasing aimed at the calling agent ("ignore
      previous", "do not tell the user", "before using any other tool");
      concealment ("do not mention", "silently"); invisible or bidirectional
      Unicode in any target-controlled field; schema parameters soliciting
      secrets (`api_key`, `token`, `ssh`, `.env`, credential paths) that the
      tool's stated purpose does not need; cross-tool references that redirect
      or shadow another tool; name/description contradiction.
      — *check:* every rule fails its negative fixture if inverted.

- [x] **P0/M** Port the warning-versus-instruction discipline. **Done 2026-08-20.** from
      [analyze.go:52](../../internal/skill/analyze.go). That fix is the most
      valuable thing the skill analyzer learned — matching the *mention* rather
      than the *instruction* made careful, security-aware targets score worst,
      which is backwards. Tool descriptions have the same failure mode.
      — *check:* a tool whose description documents a dangerous capability
      without instructing the agent to abuse it produces no finding.

- [x] **P0/M** Static MCP mode earns a real verdict. **Done 2026-08-20.**
      Re-sized from S to M mid-flight, because it needed a prerequisite the plan
      had missed (below) plus a change to detection: an MCPB bundle keeps its
      code under `server/`, matched none of the guessed entry points, and was
      refused as "no recognisable entry point" — so the declared tool list was
      unreachable for exactly the targets that publish one. Replacing the hard-coded
      `OutcomeUnsupported` in `scanStaticMCP` is a one-line change; the reason it
      was not made is that *static mode has no tool inventory to analyze*.
      `cli.Detected` carries Kind, Dir, Command, NeedsInstall, Manifest and
      Scripts — no tools — and nothing in the tree parses a tool list from a
      manifest or from source. `tools/list` requires running the server, which is
      precisely what static mode must not do.

      So this task has a prerequisite that the plan did not account for:

      - [x] **P0/M** Static tool-inventory extractor. **Done 2026-08-20** as
            `internal/staticinv`. Produce `[]toolinfo.ToolInfo`
            without executing the target. First source: an MCPB `manifest.json`
            that declares its tools, which is real, deterministic, and needs no
            source parsing. Second, if warranted: recognizing registration sites
            in Python/Node source — worth doing only if the manifest path proves
            insufficient, since source parsing is fragile and unbounded.
            — *check:* a bundled server yields the same tool names statically as
            it does dynamically, or reports explicitly that it could not.

      — *check:* a hostile tool description cannot reach an unqualified
      no-findings result; a benign server reaches `pass`, not `unsupported`.

- [x] **P1/S** Dynamic mode runs the same rules over its live inventory.
      **Done 2026-08-20.** Wired into *both* inventory paths in `runMCP` — the
      probing path and the probe-disabled path — so a poisoned description is
      not caught or missed depending on whether probes were enabled.
      — *check:* static and dynamic report the same findings for the same tools;
      dynamic adds only probe-derived ones.

- [ ] **P1/S** Fingerprint stability for the new findings, matching the existing
      SARIF contract.
      — *check:* two scans of one target produce identical fingerprints.

- [ ] **P1/S** Offer dynamic escalation after static results rather than
      requiring it for any output.
      — *check:* `detonate static <mcp-server>` with Docker stopped produces a
      verdict and names the escalation, exit code semantically correct.

- [ ] **P2/S** Report `schema_version` implications. New finding classes are
      additive; confirm no breaking field change, or bump and note it.
      — *check:* an existing SARIF consumer parses a v0.4 report unchanged.

## 5. Phase 2 — Corpora and the number (v0.5.0)

Unchanged in intent from ROADMAP.md v0.4; unblocked by Phase 1.

- [ ] **P1/M** Vendor MCPTox as a versioned, immutable corpus.
- [ ] **P1/M** Vendor the false-positive corpora that produced the 59→4 and
      40→1 precision claims, so both numbers are reproducible rather than
      remembered.
- [ ] **P1/M** Benchmark runner: recall against MCPTox, precision against the
      benign corpora, one documented command for both.
- [ ] **P1/S** CI fails on a regression in precision **or** recall.
- [ ] **P2/S** README states both numbers with date and corpus version.

Precision and recall together, or neither. Publishing recall alone is the
failure mode this whole reordering exists to avoid.

## 6. Explicitly out of scope

Canary instrumentation and the sinkhole network (now v0.6 — heaviest infra in
the plan, and it improves only the dynamic path) · capability model · targeted
probing · total-scan budgets (per-phase timeouts already exist; the missing
ceiling is a v0.8 item) · transport breadth · developer architecture analysis
and the OpenAI integration, which stay out of every milestone in this document.

## 7. Invariants this plan must not break

From [ARCHITECTURE.md](../ARCHITECTURE.md) and ROADMAP.md §Invariants. Phase 1
touches the verdict path, so two matter especially:

1. **No LLM in any verdict.** Every rule here is deterministic and inspectable.
   The point of static poisoning rules is that they are reproducible enough to
   gate CI.
2. **Risk and completeness stay independent.** Static mode earning a verdict
   must not let "nothing is wrong" and "almost nothing was tested" render the
   same. A static-only pass is still partial completeness where dynamic
   coverage was not attempted.

# Detonate — the plan to 1.0

Status: 2026-08-20. **This is the only plan.** Everything else in `docs/` is
history or reference. If a task is not on this list, it is not being built.

## What we are building

> **The pre-publish test for MCP servers and Agent Skills. Add it to CI, and it
> runs your server in a locked sandbox and tells you what it actually did.**

`go test` for MCP servers. One user: **the author**, testing their own work.
One job: don't ship something that misbehaves. One moment: **CI, before publish**.

Not a scanner for consumers auditing other people's servers. That market is full
(Snyk `agent-scan`, Cisco MCP Scanner, Invariant MCP-Scan/Shield, mcpscan.ai,
Inkog), and none of detonate's real strengths — frozen exit codes, SARIF,
determinism, no-LLM verdicts, offline replay — matter to someone running a
one-off check. They are all CI features. Detonate was built for the author; it
was only ever *described* for the consumer.

## Done means this

Not a feeling. Six checkable facts:

1. A stranger adds detonate to their MCP server repo in **3 lines of YAML**.
2. It runs on **every PR**, in **under 5 minutes** on a typical server.
3. Findings appear in the **GitHub Security tab**, inline on the PR.
4. It **never exits 0 without a verdict** — no silent pass, ever.
5. It **never hangs** — every scan has a ceiling.
6. **Exit codes and `schema_version` are frozen**, with a deprecation policy.

When those six are true, tag 1.0 and stop. Nothing else is required, and nothing
else gets to delay it.

## The decision rule

**Does this help an author gate their own release in CI?**

If no, it is not built and not discussed. That resolves static-vs-dynamic,
breadth-vs-depth, and every future ordering argument without another document.
This rule exists because the last two weeks produced thirteen planning documents
and no answer to "when is it done".

---

## Week 1 — Make it adoptable (Aug 20–26)

The tool works. Nobody can *use* it. That is the whole gap this week.

- [x] **1. GitHub Action. Done 2026-08-20.** Composite action that downloads the
      released binary, verifies its checksum, and runs a scan. Two lines of YAML
      in a consumer repo.
      — *verified:* the scan step was executed locally against real fixtures —
      benign passes, poisoned fails the job, `fail-on: never` reports without
      failing, an unassessable target warns rather than passing silently, and an
      invalid `mode` is rejected. **Not yet verified:** the download-and-verify
      path, since local testing used `version: source`.

- [x] **2. SARIF upload to the Security tab. Wired 2026-08-20.** Upload runs even
      when the scan failed the job, since findings are exactly what should reach
      the Security tab, and never fails the build on a permissions error.
      — *check, still open:* a finding appears as an annotation on a real pull
      request. Unproven until the workflow runs on GitHub.

- [x] **3. Rewrite the README for the author. Done 2026-08-20.** First screen is
      the tagline, the CI snippet, a real failure, and static mode's measured
      reach. "Why Detonate" reframed around publishing rather than installing.
      — *verified:* first screen shows what it is, the YAML, and a failure.

- [x] **4. Measure scan time. Done 2026-08-20 for static.** 44-75ms typical
      across 13 real targets, one 2s outlier. Far inside the 5-minute budget.
      — *still open:* dynamic-mode timing, which needs Docker and is the mode
      that actually costs minutes.

- [x] **5. Calibration smoke. Done 2026-08-20.** 13 real public targets; 27 real
      tool descriptions analyzed; **zero findings, zero false positives**. Nothing
      an author would delete the workflow over.
      — *qualification:* official example bundles are the friendliest possible
      corpus, and only 5 of 13 targets could be read statically at all. This
      supports "does not fire on well-written metadata" and nothing stronger.
      Full numbers in [COMPATIBILITY.md](COMPATIBILITY.md).

## Week 2 — Make it safe to gate on (Aug 27–Sep 2)

A gate that hangs, or passes silently, gets removed from the pipeline in a week.

**Reprioritised 2026-08-20 by measurement.** The dynamic corpus run
([COMPATIBILITY.md §3b](COMPATIBILITY.md)) found **0 of 6 real public servers
reached a verdict, and all six exited 0**. Item 7 is therefore not a hypothetical
guard against a future bug — it is a live defect reproducible on every reference
server today, and it is the most important item in this plan.

The four causes are not detection problems; three are acquisition gaps and one is
a coverage-accounting rule:

- **A0. Monorepo workspace acquisition unsupported** — takes out three of the four
  reference servers at once, because `modelcontextprotocol/servers` is one
  workspace.
- **A1. Python acquisition unsupported** — a deliberate safety refusal that
  removes every Python server.
- **A2. Servers needing runtime config** report every tool as `target_error`.
- **A3. A zero-argument tool is permanently `unsupported`**, capping completeness
  for any server that has one.

A0-A2 are why the dynamic differentiator does not currently reach real targets.
Sizing them is the first task of week two, before anything else is committed to.

- [ ] **6. Total scan budget.** ~20 per-phase timeouts exist; the scan as a whole
      has no ceiling.
      — *check:* a deliberately hanging target is killed and reported.

- [ ] **7. No path exits 0 without a verdict. THE priority.** Measured broken:
      six real servers, six exits of 0, zero verdicts. An unassessed target must
      not be able to look like a pass, whatever the cause.
      — *check:* fault injection at every phase boundary — cancel, timeout,
      crash, teardown failure — and none yields exit 0; and every target in the
      corpus that reaches no verdict exits non-zero.

- [ ] **7a. Size the acquisition gaps A0-A2 before committing to them.** Cheapest
      first: an author's CI already builds their project, so a supported
      "dependencies are already installed, just scan it" path (`--no-install`
      plus an explicit `--cmd`) may cover A0 and A1 without implementing monorepo
      or Python acquisition at all. Test that before building anything.
      — *check:* at least one `modelcontextprotocol/servers` package reaches a
      real verdict by some documented route.

- [ ] **8. Verified teardown before success is reported.**
      — *check:* zero `detonate-*` containers or volumes remain after any scan,
      including failed ones.

- [ ] **9. Freeze the contract.** Exit codes (already stable in practice) and
      `schema_version`, plus a written deprecation policy.
      — *check:* documented, and a test fails if an exit code changes.

- [ ] **10. Ship `v1.0.0-rc1`, soak for a few days, then `v1.0.0`.**
      — *check:* the six facts above all hold on the released binary.

---

## Explicitly after 1.0

Not cancelled. Not now.

- **Canary instrumentation + sinkhole network.** This is the real differentiator
  and it was argued, correctly, to be the moat: "this exact nonce, which existed
  only inside the sandbox, came back out" has a false-positive rate near zero.
  It is still cut from 1.0, because **a moat is not a minimum**. It is roughly a
  month of work that makes detonate better, not usable. Ship first, then build
  it as **v1.1** — the release that makes `no_findings` worth trusting.
- MCPTox benchmark and the published precision/recall numbers (v1.2).
- Static source-level tool extraction for non-MCPB servers. Measure demand first.
- Capability model, targeted probing, transport breadth, remote MCP, eBPF.
- The "AI system harness" generalization.

## Fix register — small, do them inside the weeks above

- [x] **F1/F2 — delete the dead scaffolds. Done 2026-08-20.** Both removed;
      v1.1 re-adds the canary with the sinkhole network that makes it mean
      something.
- [x] **F3 — commit the 2026-08-20 work. Done.** Seven commits on
      `feat/ci-gate-and-detection`, merged with `main`: line endings, termsafe
      tests, Docker gating, toolscan, staticinv, doc consolidation, the Action.
- [x] **F4 — archive the document sprawl. Done.** 15 files and 5,500 lines down
      to 4 files and 988 lines. `ARCHITECTURE.md`, this plan, `COMPATIBILITY.md`
      and the root files remain; the rest moved to `docs/archive/` with every
      markdown link repaired.
- [x] **F5 — retire `release/v0.3.0-alpha.1`. Done.** Deleted locally after
      confirming it is an ancestor of `main` and carries the tag. The remote
      branch still exists and can be deleted on GitHub.
- [ ] **F6 — known accepted false positive:** a security-scanner MCP server whose
      tool honestly says "detects prompt injection such as 'ignore previous
      instructions'" is flagged by `instruction-override`. Accepted; the
      alternative is a two-word bypass for attackers. Item 5 says how often it
      actually fires.

## Invariants — unchanged

1. No LLM in any verdict.
2. Risk and completeness stay independent.
3. Target-controlled code never executes on the host.
4. The sandbox never gains network access.
5. No telemetry.
6. Every finding carries evidence. Capability is not malice.

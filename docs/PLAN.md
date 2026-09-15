# Detonate — the plan to 1.0

Status: 2026-09-02. **This is the only plan.** Everything else in `docs/` is
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

- **A0. Monorepo workspace acquisition unsupported** — ~~takes out three of the
  four reference servers~~ **CLOSED 2026-08-20** by the pre-built route, without
  implementing workspace acquisition.
- **A1. Python acquisition unsupported** — **CLOSED 2026-08-20** by the same
  route. The safety refusal stands; authors build in their own CI instead.
- **A2. Servers needing runtime config** report every tool as `target_error`.
- **A3. A zero-argument tool is permanently `unsupported`**, capping completeness
  for any server that has one.

A0-A2 are why the dynamic differentiator does not currently reach real targets.
Sizing them is the first task of week two, before anything else is committed to.

- [x] **6. Total scan budget. Implemented 2026-08-2x, partially verified.**
      `scan.DefaultBudget` is 15 minutes and `scan.Run` wraps the whole pipeline
      in it, recording a required `pipeline.budget` timeout scenario so an
      overrun cannot report success.
      — *check, partly open:* `TestBudgetExceededIsReportedAndNeverLooksClean`
      proves the collapse using an already-spent budget, which needs no target.
      **Not yet proven:** a genuinely hanging target, running under a real
      deadline, is killed and reported. The fixture takes the same code path
      but does not exercise the phase that would actually have to be
      interrupted.

- [ ] **7. No path exits 0 without a verdict. THE priority.** Measured broken:
      six real servers, six exits of 0, zero verdicts. An unassessed target must
      not be able to look like a pass, whatever the cause.
      — *check:* fault injection at every phase boundary — cancel, timeout,
      crash, teardown failure — and none yields exit 0; and every target in the
      corpus that reaches no verdict exits non-zero.

      **Diagnosed 2026-09-02. Two defects, both reachable.**

      The `not_assessed` half of this shipped already: `exitForSummary` returns
      4 when nothing was examined, and four community servers proved it. What
      remains is the case where *something* was examined and the run then fell
      apart.

      - [x] **7c. `inconclusive` coverage still exits 0. Fixed 2026-09-02.** `exitForSummary` fails
        only on `failed` and `not_assessed`. So a scan where two tools pass and
        the third times out — or kills the target, leaving the rest skipped —
        lands on `risk=no_findings, completeness=inconclusive` and exits 0. That
        is the crash case from the v0.4.1 corpus run reporting green. `partial`
        keeps exiting 0 and that stays deliberate: the line is "was the coverage
        question answerable", not "was everything covered".
      - [x] **7d. Cancellation is not recorded. Fixed 2026-09-02.** `scan.Run` special-cases
        `DeadlineExceeded` only, so Ctrl-C unwinds through the probe loop as
        ordinary timeout scenarios and no `pipeline.*` scenario says the run was
        interrupted. With 7c fixed the exit code is right by accident; the
        report still does not say why.
      — *check:* one table driving all four boundaries — cancel, timeout, crash,
      teardown — through the real exit path, plus a scan-level cancellation
      test, plus a real interrupted run against a live server.
      — *verified 2026-09-02:* `TestNoFaultAtAnyPhaseBoundaryExitsClean` drives
      all four faults through `assessment.Summarize` and the real exit rule, and
      was confirmed to **fail before the fix** on three of them — cancel, budget
      and crash all returned 0. `TestCancellationIsRecordedAndNeverLooksClean`
      covers the pipeline scenario. Live runs on macOS arm64 with real Docker:
      the honest fixture exits 0 (`complete`), the thief fixture exits 3 with
      two critical findings, and a real `SIGINT` mid-probe exits 4 carrying
      `pipeline.cancelled` — that report reads `no_findings` + `inconclusive`
      with one tool passed, which is exactly what the old rule returned 0 for.
      — *still open, and this is what keeps item 7 unchecked:* the corpus half.
      "Every target in the corpus that reaches no verdict exits non-zero" has
      not been re-measured since the fix. The six servers that produced six
      zeroes have not been re-run.
      — *note:* the same hole made item 6 inert. The budget fired, recorded its
      timeout, collapsed completeness — and exited 0. A ceiling that reports
      without gating is not a ceiling.

- [x] **7a. Size the acquisition gaps. Done 2026-08-20 — A0 and A1 are closed
      without implementing either.** An author's CI already builds their project,
      so the supported answer is `--no-install` plus an explicit `--cmd`. One
      defect blocked that route: `policy.Image` was only ever set from the
      acquisition result, so skipping install left a Node server on the Python
      image and it died with `exec: "node": executable file not found`. Fixed.
      — *verified:* `servers/src/filesystem`, which fails acquisition outright,
      now launches, enumerates 14 tools and probes 12 — 8 pass, 6 target_error,
      2 unsupported. The first `modelcontextprotocol/servers` package to reach
      real dynamic testing. Documented in the README.

- [ ] **7b. Per-parameter benign inputs.** The six remaining failures on that
      server are directory-shaped tools handed a file path — `list_directory`,
      `directory_tree`, `create_directory`, `search_files`. One benign string
      cannot satisfy both shapes, so the same value is wrong for half the tools.
      This is the smallest useful slice of schema-driven generation and it is now
      the largest remaining coverage gap.
      — *check:* `servers/src/filesystem` reaches `complete`.

- [ ] **8. Verified teardown before success is reported.** Half done:
      `addTeardownFailure` records a required `pipeline.teardown` scenario whose
      `teardown_error` outcome forces completeness to `failed` and exit 1, so a
      scan that could not clean up cannot report success.
      — *check, partly verified 2026-09-02:* zero `detonate-*` containers or
      volumes remain after any scan, **including failed ones**. Confirmed after
      a full test-suite run (the passing path) and after a real `SIGINT` killed
      a live scan mid-probe (an abrupt failing path) — zero of both each time.
      **Still open:** teardown when the harness itself errors, and when the
      Docker daemon disappears mid-scan. Both were observed to be survivable
      during this session but neither was measured.

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
- Capability model, remote MCP, the "AI system harness" generalization.
- **eBPF runtime monitor, HTTP transport, prompts/resources** — now planned in
  detail below (decided 2026-09-11), no longer a one-line grab-bag.

---

## Beyond 1.0 — runtime observability and real-target coverage (decided 2026-09-11)

Two inputs drove these decisions: a competitive scan (dynamic execution is no
longer unique — WASM/sandbox MCP analyzers now exist in research), and a
corpus-fidelity review. Both point the same way: the differentiator is no longer
"we run it", it is *proof you can trust* (the nonce) and *detection of what the
stderr-based monitor structurally cannot see*.

### What the 40/51 corpus number does and does not prove

The fixtures are **protocol-faithful but structurally minimal**. Measured
against the real servers scanned this project:

| Dimension | Corpus fixtures | Real servers (measured) |
|---|---|---|
| Tools/server | 1–9, flat schemas | 11 (memory) → 682 (affiliate), nested |
| Transport | stdio only | stdio **and Streamable HTTP** |
| Surface | tools only | tools **+ prompts + resources** |
| Attack shape | one isolated attack | one subtle attack among dozens of honest tools |

So 40/51 proves **recall against isolated, known attacks**. It does **not** prove
detection when an attack is buried in a large production server, and the corpus
is blind to HTTP-transport servers and to prompts/resources entirely. That is
the gap the work below closes.

### Decision 1 — build a targeted eBPF runtime monitor (leads this work)

- **Why:** it closes the two gaps the corpus just surfaced that the stderr
  monitor cannot — persistence writes that leave no token
  (`evil-skill-covert:covert.persistence-no-token`, an open gap) and covert
  egress observed at the syscall rather than inferred from stderr
  (`evil-mcp-postmark:covert-bcc`, an open gap: a silent BCC writes nothing to
  stderr, so the stderr-inference monitor cannot see it at all). It is also the
  moat competitors are now describing.
- **Scope — targeted, NOT full syscall tracing:** `connect()`/DNS, and writes to
  a sensitive-path allowlist (`~/.bashrc`, `~/.profile`, `~/.ssh/authorized_keys`,
  cron paths). Evidence is the syscall and its arguments — deterministic, no LLM
  (invariant 1 holds).
- **Architecture:** a **host-side** privileged monitor attached to the target
  container's cgroup/PID/netns. The sandbox stays capless and non-root; eBPF
  observes it from outside. Target code still never executes on the host — the
  monitor only observes (invariant 3 holds).
- **Graceful degradation is mandatory:** Linux + privilege only. On
  Windows/macOS/no-privilege it no-ops and the scan runs exactly as today. This
  is **additive** — an absent syscall layer lowers completeness confidence, it
  must never invent a finding (invariant 2). eBPF must never become a hard
  dependency of a scan.
- **Environment (Decision 2 below):** WSL2. Verified 2026-09-11 — kernel 6.18,
  `/sys/kernel/btf/vmlinux` present, `CONFIG_BPF/BPF_SYSCALL/KPROBES=y`, so
  CO-RE eBPF works. **Setup gap:** the only WSL2 distro is Docker's internal
  `docker-desktop` backend; install a real dev distro (`wsl --install -d Ubuntu`)
  with Go, clang/llvm, and bpftool before E1.
- **The corpus is the gate.** Success is defined, not vibes: both
  `evil-skill-covert:covert.persistence-no-token` and
  `evil-mcp-postmark:covert-bcc` flip gap→caught, detected at the syscall level
  (a sensitive-path write and a `connect()` respectively) with no reliance on
  stderr.

### eBPF phased milestones

- [x] **E1 — spike in WSL2. Done 2026-09-15.** A CO-RE tracepoint on
  `syscalls/sys_enter_connect`, loaded by a cilium/ebpf (v0.22) Go userspace
  reader over a ring buffer, observed a silent `connect()` to `1.2.3.4:443` that
  the calling process never printed — the postmark BCC shape. Proven against the
  live WSL2 kernel (6.18, BTF), spike at `~/ebpf-spike`.
- [x] **E2 — sensitive-file-write probe. Done 2026-09-15.** A CO-RE tracepoint on
  `syscalls/sys_enter_openat`, filtered in-kernel to write-intent opens
  (`O_ACCMODE != O_RDONLY`) and in userspace to a persistence-path allowlist
  (`.bashrc`, `.ssh/authorized_keys`, cron, …), observed a `curl|sh` implant
  appended to `~/.bashrc` that the process never printed and that leaves no
  token. Spike at `~/ebpf-spike/e2`.
  — *the working approach, recorded so E3 needs no re-discovery:* tracepoints
  (not kprobes) on the syscall entry; `vmlinux.h` from `bpftool btf dump`;
  `bpf_probe_read_user`/`_str` for the userspace sockaddr and path; ring buffer
  to a `cilium/ebpf` reader; load with `ebpf.LoadCollectionSpec` (no bpf2go
  codegen needed); attach with `link.Tracepoint`. Loading needs root — the
  monitor is host-side, the sandbox stays capless.
- [x] **Attribution — proven 2026-09-15.** The un-proven risk before E3: E1/E2
  traced system-wide, but production must flag only the target container. A
  `BPF_MAP_TYPE_ARRAY` holds one target cgroup id (userspace writes it before
  attach), and the program drops any event whose `bpf_get_current_cgroup_id()`
  does not match. Proven: the same silent `connect()` made inside vs. outside a
  hand-made cgroup was captured only for the in-cgroup process, host processes
  ignored. On cgroup v2 the id is the cgroup dir's inode; E3 reads it from the
  Docker container instead of a hand-made cgroup — same filter.
- **E3 — integrate.** Feed events into `internal/trace` + `assessment` as a new
  `ebpf` source, with the same dedup/severity discipline the stderr monitor
  already uses. Findings only from the targeted probes; all else is observation.
  No unknowns remain after the three spikes — the open questions are build-system
  choices (how to ship the compiled `.bpf.o`: `go:embed` a committed object vs.
  compile at build behind a `//go:build linux` tag) and reading the launched
  container's cgroup id from `internal/sandbox`.
- **E4 — degradation gate.** A test proving a scan with eBPF unavailable is
  byte-identical to today, and a `DETONATE_REQUIRE_EBPF` that turns absence into
  failure on Linux CI the way `DETONATE_REQUIRE_DOCKER` does.
- **E5 — CI.** A privileged Linux job that runs it; corpus fixtures marked
  `requires_ebpf` where detection depends on it.

### The other real-target gaps (recorded, ranked; eBPF leads by decision)

1. **Streamable HTTP transport.** stdio-only today, so a whole class of real
   servers is unreachable. Biggest coverage unlock, buildable on Windows, and
   the corpus needs its first HTTP fixture.
2. **Prompts + resources.** tools-only today; a poisoned prompt or an
   exfiltrating resource is unscanned. Needs both engine support and fixtures.
3. **Corpus realism.** One subtle attack embedded among 30+ honest tools, to
   measure detection-in-noise rather than detection-of-isolated-attack — the
   fidelity gap the review named.

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

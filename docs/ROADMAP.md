# Detonate roadmap

Status: proposed, 2026-08-05.

This is the **version-level** plan: what ships in each release, what gates it,
and what is deliberately excluded. It answers "what is v0.4 and why is it not
v0.3".

## Which document do I read

Six planning documents already exist. Read them in this order and stop when
your question is answered.

| Document | Answers |
|---|---|
| **ROADMAP.md** (this) | What ships when, and in what order |
| [TASKS.md](TASKS.md) | The checklist, keyed to versions here |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Invariants a change must not break |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Component-level how, per phase |
| [RESEARCH_PLAN.md](RESEARCH_PLAN.md) | Why the canary/capability/benchmark work exists |
| [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) | Release and promotion contract |
| [COMPATIBILITY.md](COMPATIBILITY.md) | Verified live results |

This document supersedes the R0-R5 release-train table in
PRODUCTION_READINESS.md §4. The definitions of "production-ready" and
"promotable" in §3 of that document still stand and are the gates for v1.0.

## Versioning rules

**The binary and the report schema version separately.** CI consumers depend on
the JSON/SARIF shape, not on the CLI. A report carries `schema_version`, and
that number changes only on a breaking field change — never merely because the
CLI released.

- `0.x` — no stability promise on flags or report fields. Breaking changes are
  allowed within a minor bump and must appear in [CHANGELOG.md](../CHANGELOG.md).
- `1.0` — flags, exit codes, and `schema_version` become stable.
- Exit codes are frozen **now**, ahead of everything else, because a CI gate
  that changes meaning is worse than one that fails:
  `0` clean, `1` error, `2` usage/environment, `3` findings, `4` incomplete.

**v1.0 means the contract is frozen and the tool is safe. It does not mean
feature complete.** Transport breadth, eBPF, and registry-scale scanning can
all land after 1.0 without breaking anyone.

## Release ladder

Each version has one theme. A version ships when its gates pass; ordering is
fixed, dates are not.

---

### v0.1.0 — It installs

**Theme: a stranger can get a real result in five minutes.**

Nothing else matters until this is true. The public repository currently
contains a library with no `main` package.

Scope:
- Commit the entrypoint; clean-archive build verified on Linux, macOS, Windows.
- Prebuilt binaries on GitHub Releases, plus Homebrew tap and Scoop bucket.
- `--version` reports the real version, never `dev`.
- `detonate doctor` — reports Docker, images, disk, and what is missing, with
  the fix for each.
- Prompt and skill static scans work with **no Docker installed**.

Gates:
- Fresh machine, no Go toolchain: install → `detonate static ./prompt.txt` →
  real output, under five minutes, no README archaeology.
- `go install github.com/m4vic/detonate/cmd/detonate@v0.1.0` works from outside
  the repository.
- Missing Docker produces one actionable line, not a stack trace.

Explicitly not in scope: canaries, benchmark, acquisition rework.

---

### v0.2.0 — Findings you cannot argue with

**Theme: canary instrumentation.** See [RESEARCH_PLAN.md](RESEARCH_PLAN.md) §3.

The differentiator against every static scanner in the field, and the answer to
false positives — not by tuning heuristics, but by making a finding mean
"this exact nonce, which existed only inside the sandbox, came back out".

Scope:
- Four canary classes: environment, file, tool-input, network-intent.
- In-sandbox sinkhole DNS/HTTP on an internal Docker network with no gateway.
- Canary matching across plain, base64, hex, and URL encodings.
- Findings carry the nonce in `evidence`; finding **fingerprints exclude it**.

Gates:
- Each of the four classes has a positive and a negative fixture.
- A seeded canary never touched yields no finding **and** no coverage credit.
- Two consecutive scans of the same target produce identical SARIF
  fingerprints despite different nonce values.
- A policy test proves the sinkhole cannot reach the real network.
- The README limitation "tools that need the network cannot be behaviourally
  probed" is retired, with evidence.

Why before the benchmark: publishing a score against a probe set that is about
to change wastes the one number people will quote.

---

### v0.3.0 — Safe acquisition

**Theme: close the root-plus-network hole.**

The current worktree closes the root-plus-network path: networked fetch uses
wheel-only `pip download` or npm with lifecycle scripts disabled, and all
target-controlled installation/build work runs offline and non-root. Unsafe
manifest forms become explicit `acquisition_unsupported` outcomes. This still
needs maintainer review and release/CI evidence before v0.3.0 is earned.

Scope — two-phase acquisition:
1. **Fetch, network on, no execution.** `npm ci --ignore-scripts`,
   `pip download` to a wheel cache. Artifacts only.
2. **Build, network off, non-root.** Lifecycle scripts and build hooks run
   here or not at all.
- A target that genuinely requires a networked build hook becomes an explicit
  `acquisition_unsupported` scenario outcome — reduced completeness, never a
  silent privileged run.

Gates:
- An adversarial fixture whose `postinstall` attempts egress is blocked, and
  the attempt is reported.
- No acquisition path runs target code as uid 0 with network simultaneously.
- The TypeScript compile path and monorepo packages still work, or are
  reported unsupported with a named reason.

---

### v0.4.0 — Measured

**Theme: publish a number.**

Highest credibility-per-hour work in the plan. `mcp-sec-audit` reports 74.7%
(367/491) on MCPTox. Detonate's payloads already derive from MCPTox classes.

Scope:
- Run the full MCPTox benchmark; publish the score whatever it is.
- Publish precision alongside it from the existing false-positive corpora
  (59 skills → 4 flagged, all true; 40 Google plugin skills → 1, true).
- One documented command reproduces both.

Gates:
- Corpus is versioned and immutable.
- A regression in precision **or** recall fails CI.
- README states both numbers, with the date and corpus version.

Precision and recall together, or neither.

---

### v0.5.0 — Declared versus observed

**Theme: capability model.** See [RESEARCH_PLAN.md](RESEARCH_PLAN.md) §4.

Scope:
- Capability vocabulary: `file_read`, `file_write`, `command_exec`,
  `network_outbound`, `network_inbound`, `env_access`, `tool_sequence_hijack`,
  `prompt_injection`, `param_override`.
- Join declared (manifest, skill `allowed-tools`) against observed (evidence).
- Report the delta: *declares Read; observed command_exec*.

Gates:
- Every emitted capability carries evidence.
- Declared-but-unobserved is coverage, never a finding.
- Capability names frozen in the schema before release.

Not adopted: mcp-sec-audit's weighted-confidence risk score. A weighted sum is
not reproducible enough to gate CI, and risk/completeness separation already
solves the problem it addresses.

---

### v0.6.0 — Targeted probing

**Theme: spend the probe budget where sinks are.** See
[RESEARCH_PLAN.md](RESEARCH_PLAN.md) §5.

Scope:
- Rank parameters by sink likelihood from JSON Schema and naming evidence
  (`path`, `file`, `cmd`, `url`, `query`, `template`).
- Probe ranked parameters rather than uniformly; report reached-versus-total
  parameters as coverage.
- Nested and non-string schemas become reachable (today eight of the Memory
  server's nine tools are skipped for lacking top-level string fields).

Gate: targeting may change *which* scenarios run, never whether a given
scenario's outcome is deterministic.

---

### v0.7.0 — Static mode worth running

**Theme: make the no-Docker front door real.**

Static MCP mode currently records only source/manifest inventory. That is the
zero-friction entry point and it is empty.

Scope:
- Deterministic poisoning rules over tool names, descriptions, schemas,
  annotations, and metadata.
- Static mode earns a genuine verdict instead of always reporting incomplete.
- Dynamic mode becomes an offered escalation after static results, not a
  precondition for any output.

Gate: a hostile tool description cannot reach an unqualified no-findings result
without being analyzed.

---

### v0.8.0 — Budgets and lifecycle

**Theme: no path reaches exit 0 without a verdict.**

Scope:
- Total, phase, tool, call, output, and disk budgets, all bounded and visibly
  truncated.
- Cancellation, timeout, target crash, harness failure, and teardown failure
  all produce structured reports.
- Every sandbox removed, and removal **verified**, before reporting success.
- Explicit baseline approval and history, replacing auto-advance.

Gate: fault injection at every phase boundary; none yields exit 0.

---

### v0.9.0 — Transport breadth

**Theme: modern MCP.**

Scope: Streamable HTTP, current protocol revision, authorization flows,
remaining primitives (resources, prompts). Conformance profile per transport.

Gate: the compatibility corpus reruns green against the current result model.

---

### v1.0.0 — Stable contract

**Theme: promise something.**

Scope: freeze flags, exit codes, and `schema_version`. Publish the
compatibility matrix with immutable target versions, reproducible vulnerable
and benign demo fixtures, and a documented deprecation policy.

Gates — all of [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) §3.1 and §3.2,
plus:
- Three external users complete the quickstart unaided.
- Two external CI environments consume versioned JSON or SARIF.
- Released artifacts carry checksums, SBOM, provenance, and a documented
  verification command.

---

### Post-1.0

- **eBPF syscall tracing** — opt-in `--trace-syscalls`, Linux only, enrichment
  only. Never gates a verdict, never required for a scan. Sequenced here
  deliberately: it is Linux-only and needs host privileges, which would cost
  the single-binary cross-platform story that is currently the distribution
  advantage.
- Registry-scale batch scanning.
- Optional model-based evaluation, strictly outside the deterministic verdict
  path.

## Invariants across every version

These do not change, at any version, for any feature:

1. **No LLM in any verdict.** A scanner whose output changes between runs
   cannot gate CI.
2. **Risk and completeness stay independent.** "Nothing is wrong" and "almost
   nothing was tested" must never render the same.
3. **Target-controlled code never executes on the host.**
4. **The detonation sandbox never gains network access.** Observability is
   added by instrumenting the inside, never by loosening the boundary.
5. **No telemetry.** A security tool that phones home is a contradiction.
6. **Every finding carries evidence.** Capability is not malice.

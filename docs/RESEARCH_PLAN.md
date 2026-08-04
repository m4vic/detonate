# Detonate research-informed plan

Status: proposed, 2026-08-05.

This document turns published MCP-security research into concrete detonate
work. It layers onto the release trains in
[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md); it does not replace them.
Component-level work stays in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)
and invariants in [ARCHITECTURE.md](ARCHITECTURE.md).

Nothing here is shipped. Every item is a proposal with a stated gate.

## 1. What the literature establishes

Four papers matter for detonate's positioning. Two of them independently
confirm the product thesis; two supply techniques worth adopting.

| Work | Approach | Result relevant to us |
|---|---|---|
| [MCP-SandboxScan / SandScope](https://arxiv.org/abs/2601.01241) | WASI or native stdio execution, canary seeding, source-to-sink witnesses | Canary-based evidence model |
| [mcp-sec-audit](https://arxiv.org/abs/2603.21641) | Static rules + Docker/eBPF dynamic fuzzing | 74.7% on MCPTox; static scored 0% on JavaScript, dynamic 100% across languages |
| [VIPER-MCP](https://arxiv.org/pdf/2605.21392) | Taint-style source-to-sink analysis with validated PoC payloads | Executing the payload to confirm impact removes false positives |
| [MCPTox](https://arxiv.org/pdf/2508.14925) | Adversarial tool-invocation benchmark | Already the basis of detonate's 13 payloads / 7 classes |

Two findings deserve emphasis.

**Dynamic analysis is language-independent; static analysis is not.**
mcp-sec-audit's static engine scored 100% on Python and **0% on JavaScript**,
while its dynamic engine scored 100% on every language tested. Detonate probes
a running server over the MCP protocol and never parses target source, so it
inherits the language independence for free. This is a claim worth making
explicitly.

**Executed proof eliminates false positives by construction.** VIPER-MCP's
stated reason for validating payloads is that confirming genuine
exploitability removes false positives. Detonate already prints leaked bytes
in its `evidence` field. The research says that instinct is the correct one,
and the plan below generalizes it.

## 2. Gap analysis

Where detonate stands against the techniques above.

| Capability | Detonate today | Gap |
|---|---|---|
| Runs the target | Yes, Docker, hardened detonation policy | None. This is the moat. |
| Adversarial probes | 13 payloads, 7 MCPTox classes, baseline-diffed | Coverage is partial against wide schemas |
| Evidence in findings | Returned content, stderr signatures | Attributed only to what the tool returns |
| Canary seeding | None | **Missing entirely** |
| Capability taxonomy | Implicit in finding types | No declared-vs-observed model |
| Syscall observation | None; Docker events not wired to verdicts | eBPF absent |
| Egress-dependent tools | Reported `unsupported` | No way to observe intent |
| Benchmark number | Corpus counts only | No MCPTox score to compare |

## 3. Workstream A — canary instrumentation

**Priority: highest. Adopt from MCP-SandboxScan.**

Seed uniquely identifiable tokens into the sandbox before detonation, then
watch for them crossing a boundary. A canary that surfaces is a
source-to-sink witness: the tool did not merely have the capability, it
exercised it, and the token proves which source reached which sink.

Four classes, matching the paper:

| Canary | Seeded as | Witness |
|---|---|---|
| Environment | `DETONATE_CANARY_ENV_<nonce>` in the container env | Token appears in a tool response |
| File | Marked files at plausible paths (`~/.ssh/id_rsa`, `.env`, `~/.aws/credentials`) | Token content returned by a tool |
| Tool-input | Nonce embedded in probe arguments | Token reaches a log, another tool, or a response |
| Network-intent | Sinkhole DNS/HTTP resolver inside the sandbox | Resolution or request attempt recorded |

Three things this buys, in order of value:

1. **False positives approach zero.** A finding becomes "this exact nonce,
   which existed only inside the sandbox, came back out." That is not a
   heuristic and cannot be argued with. It is the strongest possible form of
   the evidence line detonate already prints.

2. **Egress-dependent tools become testable.** Today a tool that calls an
   external API fails its probe with a resolver error and is honestly reported
   as `unsupported`. A sinkhole resolver inside the sandbox lets detonate
   record *where the tool tried to connect and what it tried to send* without
   ever permitting real egress. The current README limitation —
   "tools that need the network cannot be behaviourally probed" — is retired
   without weakening the sandbox by one setting.

3. **Exfiltration becomes directly observable.** An environment canary that
   leaves via a network-intent canary is a credential-exfiltration chain
   captured end to end.

Gates:

- Canary tokens never collide with plausible target content.
- A seeded canary that is never touched produces no finding and no coverage
  credit.
- Sinkhole resolution is recorded as intent, never as successful egress, and
  the egress-denied policy is unchanged.
- Regression fixtures for each of the four classes, benign and hostile.

## 4. Workstream B — declared vs observed capability model

**Adopt from mcp-sec-audit.**

Adopt an explicit capability vocabulary and report the delta between what a
target declares and what detonate observes it do:

```
file_read   file_write   command_exec   network_outbound   network_inbound
env_access  tool_sequence_hijack   prompt_injection   param_override
```

Detonate already has both halves of the comparison — manifests and skill
`allowed-tools` frontmatter on the declared side, probe evidence on the
observed side — but no model that joins them. The join is the interesting
output: *"declares Read; observed command_exec"* is a privilege gap, and it is
exactly the mismatch the skill analyzer already special-cases. Generalizing it
turns a single detector into a reporting dimension.

Do not adopt mcp-sec-audit's weighted-confidence risk score. A weighted sum of
confidences is not reproducible enough to gate CI, and detonate's separation of
risk from completeness is a better answer to the same problem.

Gates:

- Every capability is emitted only with attached evidence.
- Declared-but-unobserved is reported as coverage, never as a finding.
- Capability names are frozen in the JSON schema before release.

## 5. Workstream C — targeted probing

**Adopt from VIPER-MCP, partially.**

Detonate's completeness reporting is honest that "the current probe set reaches
only part of many schemas." Blind payload injection across a wide schema is
low-yield. VIPER-MCP's contribution is using data-flow reasoning to choose
which parameter to attack.

Detonate does not parse target source and should not start. The available
signal is the JSON Schema of each tool plus its description. That supports a
cheaper version of the same idea:

- Rank parameters by sink likelihood from schema and naming evidence
  (`path`, `file`, `cmd`, `url`, `query`, `template`).
- Spend the probe budget on ranked parameters rather than uniformly.
- Report reached-versus-total parameters as a coverage figure, so improved
  targeting shows up as measured completeness rather than as a silent change.

Gate: targeting may change *which* scenarios run, never whether a given
scenario's outcome is deterministic.

## 6. Workstream D — syscall observation

**Adopt from mcp-sec-audit. Sequence last.**

The honest limitation in the README — "startup and invocation are observed;
syscalls are not" — is real, and eBPF is the standard answer. mcp-sec-audit
captures kernel events and serializes them for behavioural reconstruction.

Deliberately sequenced last, because:

- It is Linux-only and would fracture the single-binary cross-platform story
  that is currently detonate's distribution advantage.
- It requires elevated host privileges, which is a hard sell for a tool whose
  pitch is containment.
- Workstream A delivers a large share of the same observability at a fraction
  of the cost and on every platform.

Treat eBPF as an opt-in Linux enrichment (`--trace-syscalls`) that adds
evidence, never as a requirement for a verdict.

## 7. Workstream E — publish a benchmark number

**Highest credibility-per-hour item in this document.**

mcp-sec-audit reports **74.7% (367/491) on MCPTox**. Detonate's payloads are
already built on MCPTox classes. Running the full benchmark and publishing the
score — whatever it is — converts detonate's claims from assertion into a
comparable measurement, and it is the single fastest way to be taken seriously
by anyone who has read the literature.

Publish alongside it the false-positive corpus results already recorded in the
README (59 skills → 4 flagged, all true; 40 Google plugin skills → 1, true).
Precision and recall together, or neither.

Gate: the corpus is versioned and immutable, the score is reproducible from a
documented command, and a regression in either direction fails CI.

## 8. Sequencing

| Phase | Work | Depends on |
|---|---|---|
| R0 | Ship the release-blocker branch; tag an alpha with prebuilt binaries | — |
| R1a | **Workstream A** — canary instrumentation | R0 |
| R1b | Close the acquisition hole (root + network hooks) | R0 |
| R1c | **Workstream E** — MCPTox benchmark | R1a |
| R2 | **Workstream B** — capability model | R1a |
| R2 | **Workstream C** — targeted probing | R1a |
| R3 | Static MCP mode worth running without Docker | R2 |
| R4 | **Workstream D** — optional eBPF enrichment | R2 |

Workstream A is first because every other item is more valuable once findings
carry canary-grade proof, and because it retires a stated limitation without
weakening the sandbox.

Workstream E cannot precede A, or the published number will be measured
against a probe set that is about to change.

R1b is not optional before any public promotion. Acquisition currently runs
target-controlled hooks as root with network access, which is a hole in the
part of a security tool users assume is safe.

# Developer analysis, saved reports, and optional LLM plan

Status: Phase 1 initial bundle implemented and verified. Created 2026-08-12;
implementation authorized 2026-08-12. Later phases remain planned.

## Outcome

Turn Detonate from a security-only terminal result into an offline-first
project-understanding and runtime-verification tool for skill and MCP authors,
reviewers, and users.

The shortest journeys are:

```text
/static https://github.com/owner/repo
/dynamic https://github.com/owner/repo --save
/full https://github.com/owner/repo --save-dir ./reports/my-review
```

No model, API key, repository subpath, entry command, or output filename is
required for the common path. A model may improve architectural explanation,
but its absence must never reduce deterministic security coverage.

## Product contract

Every report separates six questions:

1. **Project** — what was discovered and which target(s) were selected.
2. **Architecture** — components, entry points, dependencies, relationships,
   and file roles supported by evidence.
3. **Development** — deterministic maintainability, packaging, documentation,
   reference, test, and configuration observations.
4. **Runtime reality** — what built, started, negotiated, executed, failed,
   or remained unsupported.
5. **Security** — evidence-backed findings and risk.
6. **Coverage** — what was inspected, executed, skipped, truncated, or not
   understood.

Security risk, completeness, scenarios, findings, failures, and exit codes are
always deterministic. LLM output is advisory, separately labeled, and cannot
create, suppress, reprioritize, or clear a security finding.

## Modes

| Mode | Deterministic behavior | Optional LLM behavior |
|---|---|---|
| `/static` | Inventory, manifests, references, source/file roles, dependency and quality rules; never execute target code | Explain architecture and development patterns from the bounded static evidence pack |
| `/dynamic` | Everything in static plus safe acquisition, startup, protocol inventory, probes, scripts, and runtime evidence | Explain differences between declared design and observed runtime behavior |
| `/full` | Repository-wide discovery and all supported static/dynamic scenarios within explicit budgets | Produce a deeper cross-component review and prioritized developer questions |

`/full` is not “use an LLM.” It is the deepest deterministic profile. Model
enrichment is orthogonal and available in any mode.

## Saving results

Saving is opt-in. Without `--save`, Detonate leaves no report bundle.

```text
/dynamic <target> --save
/dynamic <target> --save-dir ./reports/name
```

The optional path syntax should be implemented as a flag value accepted both
with `--save` alone and `--save=<path>`; if Go's standard flag parser makes
that unclear, use two explicit forms instead:

```text
--save
--save-dir ./reports/name
```

The default directory is collision-resistant and human-readable:

```text
detonate-results/<target-slug>-<UTC timestamp>-<short run id>/
```

Bundle contract:

```text
manifest.json       bundle schema, run id, Detonate version/commit, target
report.txt          ANSI-free human report
report.json         canonical deterministic detonate.report/v1 result
inventory.json      complete bounded file/target inventory and coverage state
architecture.json   deterministic project/component/relationship model
runtime.json        lifecycle, tools, scenarios, and bounded execution evidence
llm.json            optional advisory enrichment; absent when no model was used
```

Rules:

- Write to a sibling temporary directory and rename only after every required
  file is flushed; a failed save must not look complete.
- Never save the cloned repository, installed dependencies, package caches,
  raw environment, provider key, canary values, or unbounded target output.
- Redact configured secret patterns before persistence and record every
  redaction count without retaining the original.
- Apply per-file and total bundle byte limits. Truncation is explicit in the
  manifest and coverage model.
- Use owner-only permissions where the platform supports them.
- `report.txt` is plain and ANSI-free so it can be opened or shared anywhere.
- Print `[SAVED] <path>` only after atomic completion. Save failure returns a
  structured `report_save_failed` failure and a non-zero exit.
- A later `detonate report <bundle>` command renders the saved result without
  rescanning or contacting a model.

## Deterministic project inventory

Add an `internal/inventory` package with a narrow interface:

```go
Inventory(ctx context.Context, root string, limits Limits) (Project, error)
```

It walks without executing target code and records every in-scope file:

```text
path, size, digest, media/language, role, target ownership,
parsed | referenced | executed | skipped | unsupported | truncated,
reason, evidence source
```

Default exclusions include `.git`, dependency/vendor directories, build
outputs when a source equivalent exists, caches, devices, sockets, and files
outside the resolved repository root. Symlinks are resolved and containment is
enforced. File count, individual size, total bytes, depth, and archive limits
are mandatory before repository-wide discovery ships.

Do not print one line per file in the normal terminal report. Show component
and exception summaries; keep the auditable per-file record in
`inventory.json` and expose it with `detonate report --files <bundle>`.

## Deterministic architecture model

Add `internal/projectmodel` with versioned evidence types, not prose-only
heuristics:

```text
Project
  targets[]
  components[]
  files[]
  relationships[]
  developer_observations[]
```

Initial skill facts:

- `SKILL.md` metadata and instruction body.
- Referenced documents/assets and broken or escaped references.
- Bundled scripts, interpreter, invocation evidence, and test association.
- Declared tool permissions versus instructions.
- Unreferenced files, duplicate guidance, oversized instruction/reference
  boundaries, and missing examples/tests where those facts are provable.

Initial MCP facts:

- Runtime/ecosystem, manifest, lockfile, entry point, build step, transport,
  environment-variable names, and dependency groups.
- MCP tools, descriptions, input/output schemas, annotations, pagination, and
  protocol negotiation results.
- Source modules containing startup, registration, tool handlers, storage,
  network, process, and filesystem access, using parsers where available and
  conservative filename/import evidence otherwise.
- Test files associated by language convention and component proximity.
- Declared versus observed tool inventory and build/start/runtime outcomes.

Every architecture claim carries evidence references such as file path,
manifest field, tool schema, import edge, or runtime event. Filename inference
is labeled `inferred`, never `observed`.

Developer observations are a separate namespace and severity scale:

```text
good | info | improvement | blocking
```

They never change security risk. Avoid subjective claims such as “bad
architecture” unless backed by a named deterministic rule. Prefer precise
statements: “6 of 9 registered tool handlers have no associated test file.”

## Runtime reality

Extend the report pipeline with explicit stage facts:

```text
discovered, fetched, parsed, acquired, built, started, negotiated,
inventoried, invoked, observed, cleaned
```

Each fact has `pass`, `finding`, `failed`, `unsupported`, `skipped`, or
`truncated`, plus bounded evidence. The human report must state what actually
ran. “Dynamic” does not imply execution when a skill has no scripts, and a
started MCP server is not the same as successfully invoking every tool.

## Optional model layer

### Boundary

Add a provider-neutral `internal/llm` interface only after the deterministic
evidence schema exists:

```go
type Provider interface {
    Analyze(context.Context, Request) (Response, Usage, error)
}
```

The first implementation is `internal/llm/openai`. Future adapters may add
Ollama and Anthropic without changing report or inventory packages. Do not add
placeholder network code or pretend those providers work in v1.

The model receives a bounded **evidence pack**, not unrestricted filesystem
access and not a Docker/tool capability. It cannot execute code, browse, alter
the scan, or call provider-defined tools. Repository content is untrusted data
and is delimited from system instructions.

### User commands

Default:

```text
/model off
```

Interactive commands:

```text
/model                         show provider/model/status; never print keys
/model off                     deterministic-only analysis
/model openai <model-name>     enable OpenAI for this session
```

One-shot CLI equivalents:

```text
detonate full <target> --model off
detonate full <target> --model openai:<model-name>
```

`--model` must be explicit for scripts and CI. Interactive selection may be
remembered only in a user configuration file after confirmation; repository
configuration cannot enable a paid provider or select a more expensive model.

Credentials come only from `OPENAI_API_KEY` or an OS/user configuration
mechanism that does not write the secret into project files. Command history,
progress, saved bundles, errors, and debug logs must never contain the key.
If the key is absent, Detonate explains how to set it and continues with the
deterministic report unless `--require-model` was explicitly requested.

### OpenAI v1

Use the OpenAI Responses API and Structured Outputs with a strict JSON schema
for `llm.json`. The plan intentionally does not hard-code a perpetual “latest”
model. The model name is recorded exactly and may be set by CLI/config; the
shipped default must be selected and pinned during implementation using the
then-current official model documentation.

The structured response contains:

```text
summary
architecture_insights[] {claim, evidence_ids[], confidence}
developer_questions[] {question, why, evidence_ids[]}
possible_improvements[] {title, rationale, evidence_ids[], confidence}
limitations[]
```

Reject unknown fields, missing evidence IDs, out-of-bundle references, invalid
confidence values, or oversized output. One repair attempt is allowed for a
schema failure; no unbounded retries. Provider timeout, input/output token
budgets, maximum cost estimate, and cancellation are required.

The UI must show before the first API call:

```text
[MODEL] OpenAI <model-name>
[DATA]  sending bounded repository evidence to OpenAI
[COST]  configured input/output token limits
```

For local targets, remote model use requires explicit opt-in. For public URLs,
the same disclosure appears, but a repository being public does not imply that
all generated runtime evidence is safe to upload.

Official implementation references verified 2026-08-12:

- OpenAI Structured Outputs and Responses API:
  https://developers.openai.com/api/docs/guides/structured-outputs
- OpenAI model catalog:
  https://developers.openai.com/api/docs/models

### Trust and privacy

- LLM analysis is labeled `MODEL ANALYSIS — ADVISORY` in text and stored only
  in `llm.json` with provider, exact model, prompt/schema version, timestamp,
  token usage, latency, and evidence-pack digest.
- Never send raw secrets, `.env` contents, credential-like files, canary
  values, arbitrary binary files, or complete target stderr/stdout.
- Redaction occurs before request serialization; test that removed text cannot
  reappear in request logs or saved bundles.
- Treat instructions inside repository files as prompt injection. The model
  receives no tools and must cite only supplied evidence IDs.
- Model refusal, timeout, rate limit, unavailable service, invalid output, and
  budget exhaustion produce an advisory `model_status`; they do not make a
  deterministic scan fail unless `--require-model` was chosen.
- No model result is included in SARIF security findings.

## Report and schema evolution

Do not overload `detonate.report/v1` with speculative fields. First introduce
separate versioned documents:

```text
detonate.bundle/v1
detonate.inventory/v1
detonate.architecture/v1
detonate.runtime/v1
detonate.llm-analysis/v1
```

`report.json` remains the canonical security/coverage result and links to
companion documents through `manifest.json`. After consumers and fixtures
stabilize, decide whether a future `detonate.report/v2` should embed summaries.

## Delivery sequence

### Phase 0 — contracts and fixtures

- Freeze schemas, evidence IDs, redaction policy, bundle limits, and CLI
  grammar.
- Create small representative skill, MCP, monorepo, hostile-path, secret,
  binary, symlink, oversized, and prompt-injection fixtures.
- Add golden human and machine reports demonstrating the six report sections.

Gate: schemas validate; no developer/LLM observation can affect security risk,
completeness, findings, or exit code.

### Phase 1 — opt-in save bundles

- [x] Implement the initial bundle subset: `manifest.json`, ANSI-free
  `report.txt`, and redacted canonical `report.json`. Inventory,
  architecture, runtime, and LLM documents remain absent until their phases
  can populate them truthfully.
- [x] Add `internal/bundle`, `--save`, `--save-dir`, atomic writes,
  permissions, text limits, redaction accounting, and `detonate report`.
- [x] Render ANSI-free text and canonical JSON from the same in-memory result,
  rather than scraping terminal output.

Implemented 2026-08-12. Verification evidence is recorded after the Phase 1
gate below; inventory, architecture, runtime, and model documents remain
intentionally absent until their schemas have real producers.

Gate: interrupted writes leave no apparently complete bundle; secret fixtures
are absent; a saved bundle re-renders identically without source/network.

Verification, 2026-08-12:

- `go test -count=1 -timeout 20m ./...` passed.
- Race tests passed for bundle, CLI, acquisition, scan, and probe packages.
- `go vet ./...` passed.
- A real static scan of `https://github.com/m4vic/socratic` saved exactly the
  three allowlisted files, exited 0 with complete coverage, and the saved
  report re-rendered through `detonate report` without rescanning.
- Automated fixtures verify secret removal, valid redacted JSON, ANSI-free
  text, byte limits, temporary-directory cleanup, no overwrite, identical
  offline re-rendering, and clean JSON stdout when saving.
- A scriptless skill selected through dynamic mode does not require Docker;
  it records `skill.runtime` as skipped and states that no target code ran.
- Node MCP servers now launch from the acquired `/deps/app` runtime tree even
  without a compile step, keeping source beside its installed `node_modules`.

### Phase 2 — inventory and multi-target discovery

- Build bounded, contained traversal and file-role classification.
- Discover all skill/MCP targets recursively, deduplicate nested ownership,
  show a selection only when ambiguity cannot be resolved safely, and aggregate
  independent target results.

Gate: `/static <repo-url>` and `/dynamic <repo-url>` need no `--path` for known
repository shapes; one broken target does not erase other results.

### Phase 3 — deterministic architecture and developer analysis

- Implement evidence-backed project/component/relationship types and the
  first skill/MCP developer rules.
- Add Project, Architecture, Development, Runtime Reality, Security, and
  Coverage renderers.

Gate: every claim resolves to valid evidence; file inventory accounts for all
in-scope files; false-positive fixtures do not receive subjective warnings.

### Phase 4 — `/full` profile

- Compose repository-wide static and dynamic analysis with explicit total,
  target, phase, output, disk, and file budgets.
- Add partial aggregate results and resume-safe saved evidence where feasible.

Gate: full scans remain bounded, truthful, and useful without an LLM.

### Phase 5 — OpenAI advisory enrichment

- Implement the provider interface and OpenAI Responses API adapter.
- Add `/model`, `--model`, `--require-model`, consent disclosure, structured
  schema validation, evidence citation checks, cost/token budgets, and
  `llm.json`.
- Add record/replay fixtures so ordinary tests do not call a paid API.

Gate: offline scans are unchanged; API failures degrade safely; injected
repository instructions cannot trigger tools or uncited claims; an opt-in live
test against a public fixture succeeds and records exact provider/model/usage.

### Phase 6 — evaluation and future providers

- Build a reviewed corpus of architecture facts, useful developer observations,
  unsupported questions, injections, and secret-bearing repositories.
- Compare deterministic-only and OpenAI-enriched usefulness, factuality,
  citation correctness, latency, and cost.
- Add Ollama next for local/private analysis, then consider Anthropic only from
  its official API contract. Each adapter must pass the same conformance suite.

Gate: model enrichment demonstrates measurable value over deterministic output
without weakening privacy, cost, reproducibility, or security boundaries.

## Testing matrix

- Unit: traversal, containment, roles, evidence IDs, redaction, schemas,
  atomic paths, CLI grammar, model status, and token/cost budgets.
- Contract: bundle document schemas, provider interface, OpenAI request and
  structured response validation, backward-compatible `report.json`.
- Integration: real Git clone, skill/MCP inventory, Docker runtime, cleanup,
  save/re-render, provider 401/429/500/timeout/refusal/malformed output.
- Security: symlink/path escape, terminal escape, prompt injection, secret
  exfiltration, oversized files/output, malicious filenames, archive bombs,
  and repository config attempting to enable a provider.
- Evaluation: fixed deterministic and model-enriched corpus with claim-level
  evidence precision, unsupported/abstention quality, latency, tokens, and
  estimated cost.
- Live/manual: public GitHub skill and MCP repository, interactive `/model`
  disclosure, one opt-in OpenAI call, saved bundle inspection, and post-run
  container/volume audit.

Paid live tests are opt-in and never required for contributors without a key.
CI uses replayed, schema-valid provider fixtures plus a separately protected
scheduled/release lane if maintainers authorize API spend.

## Top risks and controls

| Risk | Control |
|---|---|
| Fluent model prose is mistaken for a verified fact | Separate advisory document, mandatory evidence IDs, visible label, deterministic verdict authority |
| Private code or secrets are sent to an API | Explicit opt-in, pre-serialization redaction/exclusions, request audit metadata, local provider planned next |
| “Every file” becomes unusable noise | Complete machine inventory; component and exception summaries in human output |
| Model calls create surprise cost or latency | Off by default, exact model disclosure, token/call/time/cost budgets, no unbounded retries |
| Repository prompt injection controls analysis | Repository is untrusted data, no model tools, strict schema, evidence allowlist, injection corpus |
| Save bundles leak or become huge | Allowlist documents, no source/cache copies, redaction, byte limits, permissions, atomic completion |
| Architecture heuristics overclaim | Observed/inferred distinction, evidence for every claim, explicit unsupported state |
| Provider abstraction becomes speculative complexity | One real OpenAI adapter first; add another only after conformance needs are demonstrated |

## Decisions recorded

- Offline deterministic operation is mandatory and is the default.
- Optional LLM analysis is additive and non-gating.
- OpenAI is the only initial remote provider implementation.
- Ollama/local and Anthropic are future adapters, not v1 claims.
- Model selection is explicit and recorded; repository content cannot enable it.
- Save is opt-in and produces a bounded review bundle, never a source archive.
- Per-file accountability lives in machine inventory; humans see summarized
  architecture and meaningful exceptions.

## Completion definition

This initiative is complete only when a new user can paste a real GitHub URL,
choose static/dynamic/full, optionally add `--save`, receive useful developer
and security understanding without any model, optionally enable OpenAI with a
clear data/cost disclosure, and later reproduce exactly what was deterministic,
what actually ran, what was sent to the provider, and what remained unknown.

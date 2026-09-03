# Changelog

All notable user-visible changes are recorded here. The project follows
[Semantic Versioning](https://semver.org/) once versioned prereleases begin.

## Unreleased

### Fixed

- **A scan that lost its target still exited 0.** `not_assessed` was already
  caught, so a target nothing could be learned from failed correctly. What was
  missed is the case where *something* was learned and the run then fell apart:
  two tools pass, the third times out or kills the server, the rest are never
  reached. That lands on `risk=no_findings` beside `completeness=inconclusive`,
  and the exit rule only failed on `not_assessed` and `failed` — so it exited 0.
  This is the crash case from the v0.4.1 corpus run reporting green to CI.
  Inconclusive coverage now exits 4.

  The same hole swallowed the total scan budget added in v0.4.0. A scan killed
  by its own 15-minute ceiling recorded the timeout, collapsed completeness to
  inconclusive — and exited 0 anyway. The ceiling was reporting without gating.

  `partial` still exits 0 and that line is deliberate: partial means the
  coverage question was answered and the answer was "some of it". Inconclusive
  means required scenarios started and never finished, so there is no answer.

- **Ctrl-C left no trace in the report.** The probe loop unwinds cleanly on
  cancellation, so an interrupted scan looked like one that finished quickly
  with fewer results. A `pipeline.cancelled` scenario and a `scan_cancelled`
  failure now name it, matching how a budget overrun is already recorded.
  Verified against a live server interrupted mid-probe: exit 4, the
  cancellation named in the report, and no containers or volumes left behind.

### Changed

- CI and release workflows build with Go 1.27 (was 1.25). `go.mod` still
  requires only Go 1.25, so building from source is unaffected.

## v0.4.1 — 2026-08-23

First corpus run against servers written by people who have never seen
detonate, taken from the official MCP registry. Fixtures are written by the same
author as the rules, so this class of defect was structurally invisible until
now. All three of these shipped in v0.4.0.

### Fixed

- **One dead socket was reported as 935 findings.** A 682-tool server returned
  949 findings in total. A payload killed the server process, and every
  subsequent call — across every remaining tool — returned
  `connection closed: client is closing: EOF`, each recorded as that tool
  crashing under hostile input. The first crash is kept, because a payload that
  kills the target *is* the result; what stops is treating the corpse as
  evidence about tools that were never reached. The scan now halts and reports
  how many tools went unprobed. That server went from 949 findings to 4.
- **A two-digit leak marker.** The template-injection probe sent `{{7*7}}` and
  searched responses for `"49"`, so a benign error carrying
  `"timestamp": "2026-08-23T13:15:54.497Z"` was reported as CRITICAL
  server-side template injection — `.497` contains `49`. One report from that
  scan held 33 incidental occurrences. The payload is now `{{31337*31337}}`
  matched against `982007569`, the same standard the credential decoys already
  meet with a 128-bit nonce.
- **Tool shadowing fired on ordinary documentation**, for two separate reasons.
  A directive anywhere in a description paired with a tool name anywhere else in
  it, which on a server whose 682 tools all share a prefix is close to
  guaranteed — and two of three findings displayed evidence that did not contain
  the trigger at all. Both must now appear in the same sentence, and the
  evidence is that sentence.

### Changed

- **Redirection and sequencing are no longer the same finding.** A description
  that supersedes or suppresses another tool ("call this **instead of**
  `get_weather`") remains a CRITICAL finding. A description that orders calls
  within one workflow ("**always call** `read_docx` **before** any
  accept/reject/reply") is now an observation to confirm. A real registry server
  ships exactly that sentence as a correctness constraint and was reported
  CRITICAL for it. Structurally the two are identical and only intent separates
  them — capability is not malice, the same lesson `internal/skill` learned when
  flagging 30 of 59 known-good skills.

### Added

- `scripts/find-targets.py`, which finds servers detonate can actually probe by
  reading the official registry. Of the first 400 entries, 289 are remote-only
  (an endpoint someone else operates, with no code to sandbox), 3 require API
  keys, and 33 are probeable.

## v0.4.0 — 2026-08-23

### Added

- **A GitHub Action.** Two lines of YAML run a scan on every push, fail the job
  on findings, and publish SARIF to Security → Code scanning. The released
  binary's checksum is verified before it runs.
- **Credential decoys.** The sandbox is furnished with plausible SSH keys, cloud
  credentials, a `.env`, a `.netrc`, a GitHub token and shell history, each
  carrying a unique 128-bit token that exists nowhere else. A tool that returns
  one has leaked a credential, and the nonce is in the evidence — there is no
  benign explanation to argue about.
- **A bounded proven-negative.** A clean scan now asserts what it proved
  ("planted 6 credential decoys in the sandbox; none were returned by any tool")
  rather than only reporting an absence.
- **MCP tool-metadata analysis** (`internal/toolscan`): instruction injection,
  concealment, tool shadowing, pseudo-system markup, invisible Unicode tag
  smuggling (decoded into the evidence), bidi overrides, and credential-
  soliciting schema parameters. Deterministic, no model involved.
- **A static verdict for MCPB bundles** (`internal/staticinv`): the declared
  tool inventory is read from `manifest.json` without executing anything, and
  `tools_generated` correctly reduces completeness rather than implying a full
  list.
- **A total scan budget**, defaulting to 15 minutes. An overrun is a required
  timeout scenario, so no path can report success after one.
- **`DETONATE_REQUIRE_DOCKER`**: turns Docker-gated test skips into failures, so
  CI cannot report green having exercised none of the sandbox invariants.

### Changed

- **Nested input schemas are probed.** Payloads now reach strings inside arrays
  and objects, not only top-level parameters. A tool whose arguments are an
  array of objects previously reported "no adversarial string-input surface" and
  was never probed at all. On the official MCP memory server this took tools
  with a reachable attack surface from 3 of 11 to 10 of 11. The walk is bounded
  by depth and a leaf cap, because the schema is written by the target.
- **The sandbox no longer takes the blame for its own restrictions.** A tool
  that fails because the root filesystem is read-only is reported as
  `unsupported` naming the restriction, matching how denied egress was already
  handled. Six of the memory server's tools were recorded as broken for failing
  to write to a filesystem detonate had mounted read-only on purpose. `EACCES`
  alone does not qualify: a tool refusing to read `/etc/shadow` is working
  correctly, and that is a different fact.
- **A scan that assessed nothing no longer exits 0.** Exit 0 means "no
  findings", and a pipeline reads it as "safe to merge". Four real community MCP
  servers returned `not_assessed` and exited clean. Risk `not_assessed` now
  exits 4. This is narrower than `--fail-incomplete`: partial coverage still
  exits 0, because something was genuinely assessed and nothing was found.
- **Zero-argument tools are now called once, benignly, when a decoy is present**
  and their response checked for planted secrets. They were previously never
  invoked at all, so a tool returning a credential on every call could not be
  detected. Their scenario outcome stays `unsupported`: the adversarial probe
  set genuinely does not reach them.
- **Benign probe arguments are built from the target's own schema** — a
  directory for directory operations, the first permitted value for enums, and
  minimal valid values for required non-string parameters. On the official
  filesystem server this took passing tools from 8 of 14 to 14 of 14; every one
  of those failures was detonate blaming a working server for arguments detonate
  had built wrong.
- The sandbox runtime image is now chosen from the detected ecosystem even when
  `--no-install` skips acquisition, which is what makes the pre-built route work.
- The README leads with the author testing their own server in CI, rather than
  with consumers installing third-party ones.

### Fixed

- **The credential decoy was unreadable inside the sandbox on Linux.** Files
  were planted `0600`; the sandbox runs as uid 1000 while the files are created
  by whoever ran detonate, so ownership never matched and the target could not
  open the credentials it was being tempted with. Nothing leaked, and scans
  reported clean results they had not earned. It survived because Docker Desktop
  on Windows and macOS ignores POSIX ownership on bind mounts, so every local
  run passed; the first CI run on Linux caught it. Files are now `0644` and
  directories `0755`, applied with an explicit `chmod` after creation because
  `os.WriteFile` masks its mode by the umask.
- `detonate static --help` treated `--help` as a file path and answered that it
  did not exist. Every subcommand now prints usage, options, and exit codes.
- The startup banner's box was two characters wider on four lines than the rules
  above and below, and its version field overflowed for any build from an
  untagged commit — which is every build a contributor makes.
- `version: latest` in the GitHub Action failed on every run: piping curl into
  `grep -m1` closed the pipe, curl exited 23, and `pipefail` failed the step.
- Decoy findings rendered no evidence line, so the nonce that makes them
  checkable was invisible to the reader.
- `docker run` arguments were emitted from a Go map, so the same scan produced a
  different invocation every time.
- Line endings are normalized by `.gitattributes`; `gofmt -l` and
  `go mod tidy -diff` previously reported false failures on Windows.

### Removed

- `probe.GenerateCanary` and `monitor.WatchContainer`, which had no non-test
  callers. Unwired scaffolding is what made v0.2 look shipped when it was not.


### Added

- Independent risk and scan-completeness results.
- Scenario-level outcomes for MCP inventory, tool probes, skill analysis, and
  skill scripts.
- `--fail-incomplete` with exit code 4.
- Lossless MCP tool results, including structured content and `isError`.
- Bounded, cursor-aware MCP `tools/list` pagination.
- Structured JSON/SARIF reports for early fetch, runtime, acquisition, MCP
  startup/inventory, and skill-load failures.
- Opt-in `--save`/`--save-dir` report bundles with redacted JSON, ANSI-free
  text, offline replay, and target/runtime provenance.
- Semantic terminal colors and labeled scan, finding, observation, failure,
  and saved-result output, with `NO_COLOR` and `--color` support.
- Clean-archive build, install, version, and prompt smoke tests across Linux,
  macOS, and Windows.
- Production-readiness, architecture, compatibility, security, support, and
  contribution documentation.

### Fixed

- The executable ignore rule no longer hides `cmd/detonate/main.go`.
- Go-installed binaries can obtain their module version from build metadata.
- Python missing-module messages no longer match Node network errors.
- Concealment wording no longer suppresses a separate credential-access
  finding on the same line.
- Benign MCP `isError` results no longer count as successful probe coverage.
- Node targets now launch from the acquired source tree beside their installed
  `node_modules`, including non-compiled packages.
- Cleanup/teardown failures now affect completeness and are retained as
  structured failures instead of being discarded.
- Zero-argument tools no longer claim that adversarial payloads were sent; the
  report names the missing string-input surface.

### Security

- Release publication now depends on formatting, vet, race, test, tracked
  entrypoint, and Docker verification gates.
- Dependency acquisition is split into a networked inert fetch and an offline,
  non-root lifecycle/build phase; mutable sandbox image tags are digest-pinned.

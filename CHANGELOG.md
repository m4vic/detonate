# Changelog

All notable user-visible changes are recorded here. The project follows
[Semantic Versioning](https://semver.org/) once versioned prereleases begin.

## Unreleased

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

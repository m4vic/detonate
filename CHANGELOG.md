# Changelog

All notable user-visible changes are recorded here. The project follows
[Semantic Versioning](https://semver.org/) once versioned prereleases begin.

## Unreleased

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

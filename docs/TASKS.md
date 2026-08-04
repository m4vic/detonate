# Detonate task list

Status: proposed, 2026-08-05. Keyed to [ROADMAP.md](ROADMAP.md).

Checklist form, ordered by version. Each task states its acceptance test, not
just its intent. A task is done when its check passes, not when the code exists.

Legend: **P0** release/safety blocker · **P1** required for trustworthy release
· **P2** adoption · **P3** advanced. Size **S** days · **M** 1-2 weeks · **L** multiple weeks.

---

## v0.1.0 — It installs

- [x] **P0/S** Anchor ignore patterns to repo root (`/detonate`, `/detonate.exe`)
      — *check:* `git ls-files cmd/detonate/main.go` returns the file
- [x] **P0/S** Commit `cmd/detonate/main.go`
      — *check:* `git archive HEAD` into an empty dir, `go build ./cmd/detonate` succeeds
- [x] **P0/S** Clean-archive CI lane on Linux, macOS, Windows
      — *check:* lane fails if the entrypoint is removed
- [x] **P0/S** Gate release publication on a green CI conclusion
- [ ] **P0/S** Merge the R0 branch to `main`
      — *check:* `main` builds from a fresh clone
- [ ] **P0/S** Real version via `-ldflags` + `debug.ReadBuildInfo` fallback
      — *check:* `go install ...@v0.1.0` then `--version` prints `v0.1.0`, not `dev`
- [ ] **P1/S** `detonate doctor` — Docker, images, disk, permissions
      — *check:* on a machine without Docker, prints one actionable line per gap
- [ ] **P1/S** Missing Docker degrades to static mode instead of erroring
      — *check:* `detonate static ./prompt.txt` succeeds with Docker stopped
- [ ] **P1/M** Release binaries: GoReleaser → GitHub Releases + checksums
      — *check:* three OS artifacts download and run
- [ ] **P2/S** Homebrew tap and Scoop bucket
- [ ] **P2/S** README quickstart rewritten around the evidence line, with a
      comparison table naming which scanners execute the target and which do not
- [ ] **P1/S** Tag `v0.1.0`
      — *check:* fresh machine, install → first real result, under five minutes

## v0.2.0 — Canary instrumentation

- [ ] **P1/M** Canary token generator: high entropy, fresh per scan, collision-checked
      — *check:* generated token never matches plausible target content in the corpus
- [ ] **P1/M** Environment canaries seeded into the container env
      — *check:* fixture tool that echoes `env` produces a finding; one that does not, does not
- [ ] **P1/M** File canaries at plausible paths (`~/.ssh/id_rsa`, `.env`, `~/.aws/credentials`)
      — *check:* path-traversal fixture returns canary content; benign read tool does not
- [ ] **P1/M** Tool-input canaries embedded in probe arguments
      — *check:* token reaching a second tool or a log is witnessed
- [ ] **P1/L** Network-intent sinkhole: DNS + HTTP catch-all on an internal
      Docker network with **no gateway**
      — *check:* policy test proves no route to the real network exists
- [ ] **P1/M** Canary matching across plain, base64, hex, URL encodings
      — *check:* a fixture that base64-encodes the token before returning it is still caught
- [ ] **P0/S** Finding fingerprints exclude nonce values
      — *check:* two consecutive scans produce byte-identical SARIF fingerprints
- [ ] **P1/S** Untouched canary yields no finding and no coverage credit
      — *check:* benign target reports the canary scenarios as run-and-clean, not as covered-by-default
- [ ] **P1/S** Retire the README "tools that need the network cannot be
      behaviourally probed" limitation
      — *check:* an egress-dependent fixture yields recorded intent, not `unsupported`

## v0.3.0 — Safe acquisition

- [ ] **P0/L** Split acquisition into fetch (network, no execution) and build
      (no network, non-root)
      — *check:* no path runs target code as uid 0 with network simultaneously
- [ ] **P0/M** `npm ci --ignore-scripts`; lifecycle scripts only in the offline phase
- [ ] **P0/M** `pip download` to a wheel cache, then offline install
- [ ] **P0/S** `acquisition_unsupported` outcome for targets needing a networked build hook
      — *check:* reported as reduced completeness, never a silent privileged run
- [ ] **P0/M** Adversarial fixture: `postinstall` attempting egress
      — *check:* blocked **and** reported
- [ ] **P1/M** TypeScript compile and monorepo packages still build, or report
      unsupported with a named reason
- [ ] **P1/S** Remove the acquisition warning from README once the boundary holds

## v0.4.0 — Measured

- [ ] **P1/M** Vendor MCPTox as a versioned, immutable corpus
- [ ] **P1/M** Benchmark runner producing recall against MCPTox
      — *check:* one documented command reproduces the score
- [ ] **P1/S** Precision run over the existing false-positive corpora
- [ ] **P1/S** CI fails on a regression in precision **or** recall
- [ ] **P2/S** Publish both numbers in README with date and corpus version
- [ ] **P2/S** Vulnerable and benign demo fixtures anyone can scan in 30 seconds

## v0.5.0 — Capability model

- [ ] **P2/M** Capability vocabulary frozen in the report schema
- [ ] **P2/M** Declared side: manifest and skill `allowed-tools` extraction
- [ ] **P2/M** Observed side: map evidence to capabilities
- [ ] **P2/S** Report the declared-versus-observed delta
      — *check:* a skill declaring `[Read]` that shells out reports a privilege gap
- [ ] **P2/S** Declared-but-unobserved renders as coverage, never as a finding

## v0.6.0 — Targeted probing

- [ ] **P2/M** Sink-likelihood ranking from schema and parameter naming
- [ ] **P2/M** Reach nested and non-string schemas
      — *check:* the Memory server's currently-skipped 8 of 9 tools are probed
- [ ] **P2/S** Report reached-versus-total parameters as coverage
- [ ] **P2/S** Determinism guard: targeting changes which scenarios run, never
      whether an outcome is deterministic

## v0.7.0 — Static mode worth running

- [ ] **P1/M** Deterministic poisoning rules over tool names, descriptions,
      schemas, annotations, metadata
      — *check:* a hostile description cannot reach unqualified no-findings
- [ ] **P2/M** Static MCP mode earns a real verdict instead of always incomplete
- [ ] **P2/S** Offer dynamic escalation after static results
      — *check:* the first run produces value with Docker absent

## v0.8.0 — Budgets and lifecycle

- [ ] **P0/M** Total, phase, tool, call, output, and disk budgets
      — *check:* each bound is visibly truncated in the report, never silently
- [ ] **P0/M** Cancellation, timeout, crash, harness failure, teardown failure
      all emit structured reports
      — *check:* fault injection at every phase boundary; none yields exit 0
- [ ] **P0/M** Verify sandbox removal before reporting success
- [ ] **P1/M** Explicit baseline approval and history, replacing auto-advance
      — *check:* a changed tool description requires acknowledgement

## v0.9.0 — Transport breadth

- [ ] **P2/L** Streamable HTTP transport
- [ ] **P2/M** Current protocol revision and authorization flows
- [ ] **P2/M** Resources and prompts primitives
- [ ] **P2/M** Conformance profile per transport
- [ ] **P2/S** Rerun the compatibility corpus against the current result model

## v1.0.0 — Stable contract

- [ ] **P1/S** Freeze flags, exit codes, `schema_version`
- [ ] **P1/S** Deprecation and migration policy
- [ ] **P1/M** Compatibility matrix with immutable target versions
- [ ] **P1/M** SBOM, provenance attestation, signatures, verification command
- [ ] **P1/S** Three external users complete the quickstart unaided
- [ ] **P1/S** Two external CI environments consume versioned JSON or SARIF

## Post-1.0

- [ ] **P3/L** `--trace-syscalls` eBPF enrichment, Linux only, never gates a verdict
- [ ] **P3/L** Registry-scale batch scanning
- [ ] **P3/M** Optional model-based evaluation, outside the deterministic verdict path

---

## Standing checks

Run before every tag, at every version:

- [ ] `go vet ./...` clean
- [ ] `gofmt -l .` empty
- [ ] `go test -count=1 -race ./...` green
- [ ] Clean-archive build on all three platforms
- [ ] No invariant in [ROADMAP.md](ROADMAP.md) weakened
- [ ] [CHANGELOG.md](../CHANGELOG.md) updated, breaking changes named

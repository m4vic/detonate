# Terminal UI implementation plan

Status: implemented and locally verified 2026-08-12; maintainer review pending.

## Outcome

Make interactive Detonate output distinguish user input, target metadata,
progress, observations, findings, failures, and the final verdict at a glance.
Color is an enhancement; ASCII labels preserve meaning without color.

## Contract

- Human terminal output uses a centralized semantic theme.
- Color modes are `auto`, `always`, and `never`; invalid values are usage
  errors.
- `auto` colors only an interactive terminal and honors `NO_COLOR`.
- JSON, SARIF, output files, redirected stdout, and pipes contain no ANSI
  escapes.
- Existing exit codes and machine-report schemas do not change.
- Target-controlled evidence is visibly subordinate to scanner-authored text.
- Windows and non-Unicode terminals remain readable through plain ASCII labels
  when colors are unavailable.

## Work

- [x] Add terminal capability detection and semantic style primitives.
- [x] Add global and mode-level `--color auto|always|never` parsing.
- [x] Restyle interactive prompt, target summary, progress, verdict,
  observations, findings, failures, and doctor output.
- [x] Correct stale interactive acquisition wording.
- [x] Add tests for forced color, disabled color, `NO_COLOR`, redirected and
  machine output, and invalid mode handling.
- [x] Run format, vet, regular tests, race tests, and a real public-repository
  scan; inspect forced-color output and parse the corresponding JSON stream.

## Verification evidence

- `go vet ./...`
- `go test -count=1 -timeout 20m ./...`
- `go test -race -count=1 -timeout 20m ./internal/cli`
- Real colored dynamic scan of `https://github.com/m4vic/socratic`
- Corresponding JSON scan parsed as `detonate.report/v1` with no ANSI bytes
- Post-scan Docker audit found zero Detonate containers and volumes

## Non-goals

- Full-screen TUI, mouse interaction, animation, or a desktop/web interface.
- Changes to JSON/SARIF schemas, verdict rules, or scan behavior.

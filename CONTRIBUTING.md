# Contributing

Detonate welcomes focused bug fixes, compatibility fixtures, documentation
corrections, and security improvements.

## Development setup

Requirements:

- Go 1.25 or newer;
- Docker for sandbox and integration tests;
- Git.

From a clean checkout:

```text
go build ./cmd/detonate
go vet ./...
go test -count=1 ./...
```

On Linux, run the race-enabled release gate:

```text
go test -race -count=1 -timeout 25m ./...
```

Before submitting a change, also check formatting:

```text
gofmt -w <changed-go-files>
git diff --check
```

## Safety invariants

Changes must preserve these properties:

- target code is never launched directly on the host;
- detonation runs without network access, as a non-root user, with a read-only
  root filesystem and dropped capabilities;
- acquisition and detonation remain separate phases;
- cancellation and every error path attempt teardown;
- incomplete or unsupported checks cannot become an unqualified clean result;
- machine reports remain valid standalone JSON or SARIF;
- untrusted output is bounded before it is retained or rendered.

Any intentional change to a safety boundary must include tests and update the
architecture, compatibility notes, and user-facing help in the same pull
request.

## Pull requests

Keep each pull request reviewable and describe:

1. the failure or capability being addressed;
2. the security boundary affected;
3. tests and real targets used;
4. remaining limitations;
5. documentation or report-schema changes.

Do not commit credentials, private server source, generated baselines, local
`.ctx` state, or captured evidence containing secrets.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a
normal pull request or public issue.


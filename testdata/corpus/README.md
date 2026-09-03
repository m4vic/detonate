# Detection corpus

Deliberately malicious fixtures with a **known planted-vulnerability count**,
used to measure what detonate actually detects.

The existing calibration in the README measures the other direction: false
positives against real, known-good targets. That answers "does it stay quiet on
honest code" but says nothing about "does it catch what is actually there". A
scanner can score perfectly on the first question by detecting nothing at all.

Each fixture ships a `ground-truth.yaml` naming every vulnerability planted in
it, where it lives, and how detonate is expected to surface it. `corpus_test.go`
runs the real pipeline over the fixture and scores detected-against-planted, so
detection capability is a number that moves when the code changes, rather than a
claim in a README.

## The fixtures

| Fixture | Kind | Planted |
|---|---|---|
| `evil-mcp` | MCP server | 10 |
| `evil-skill` | Skill | 10 |

Both have honest twins already in the repo — `testdata/honest` and
`testdata/benign-formatter` — which is what keeps the score meaningful in both
directions.

## Expectation classes

Not every planted item should become a *finding*. detonate deliberately
separates two things, and the manifest records which is expected:

- **`finding`** — critical or notable; drives the verdict. Injection,
  concealment, credential exfiltration.
- **`observation`** — informational context for a reviewer. Capability signals
  like "uses shell" or "references an API key" are *not* findings, because
  flagging them is what made earlier revisions report 30/59 honest skills as
  suspicious. A corpus that demanded findings for these would be scoring the
  scanner against a bug.

## These fixtures are inert

They are written to be caught, not to work:

- Credential reads target only the **planted decoys** inside the sandbox home,
  whose contents are per-run nonces, not real secrets.
- Network egress targets `.invalid` (RFC 2606 reserved, resolves nowhere) and
  the sandbox denies egress regardless.
- Destructive commands appear **only as instruction text** for the analyser to
  read. No script here deletes anything.

They still run only inside the sandbox: network off, read-only root, non-root,
all capabilities dropped.

# Detection corpus

Deliberately malicious fixtures with a **known planted-vulnerability count**,
used to measure what detonate actually detects — and, just as importantly, what
it does not yet.

The calibration in the top-level README measures the other direction: false
positives against real, known-good targets. That answers "does it stay quiet on
honest code" but says nothing about "does it catch what is actually there". A
scanner can score perfectly on the first question by detecting nothing at all.

Each fixture ships a `ground-truth.yaml` naming every vulnerability planted in
it, where it lives, and how detonate is expected to surface it. `corpus_test.go`
discovers every fixture, runs the real pipeline over it, and scores
detected-against-planted, so detection capability is a number that moves when
the code changes rather than a claim in a README.

## The workflow

This corpus is meant to grow, and growing it is how detonate improves:

1. Think of an attack, or a harder variant of one already here.
2. Add a fixture directory with a `ground-truth.yaml`. No test code changes —
   discovery is by directory.
3. Run it. What detonate catches confirms a capability; what it misses is
   recorded as a `known_gap`.
4. **The set of `known_gap`s is the roadmap.** Closing one is a detector change
   that flips its fixture entry from gap to caught — and the gate fails until
   the manifest is updated to say so, so the roadmap cannot silently rot.

## Current score

Run `go test ./internal/scan -run TestCorpus -v` for the live numbers.

| Fixture | Kind | Detected / planted | What it probes |
|---|---|---|---|
| `evil-mcp` | MCP | 11 / 12 | breadth: exfil, five poisoning shapes, unicode, shadowing, traversal, egress |
| `evil-mcp-encoding` | MCP | 2 / 6 | credential-exfil **encoding** robustness |
| `evil-mcp-injection` | MCP | 2 / 6 | description-injection **phrasing** robustness |
| `evil-skill` | Skill | 10 / 10 | breadth: injection, permission mismatch, script exfil |
| `evil-skill-obfuscated` | Skill | 1 / 5 | skill-injection **phrasing** robustness |
| `evil-skill-exfil` | Skill | 2 / 4 | exfil **channel** robustness (encoding + write-to-file) |

The honest twins already in the repo — `testdata/honest` and
`testdata/benign-formatter` — are the control, and `TestCorpusHonestTwinsStay
Quiet` fails if either produces a finding. Without them a scanner that flags
everything would score perfectly above.

## Gaps this corpus has surfaced

Recorded, not hidden — an evasion nobody has written down is one nobody is
working on:

- **Output-transform exfiltration.** The decoy matcher recognises plain,
  base64, and hex. A tool or script that reverses, rot13s, gzips, or
  space-separates a secret on the way out leaks undetected.
- **The SSH-key decoy is base64-only.** Its file holds `base64(token)`, never
  the raw token, so *any* transform on top of it — even plain hex — evades the
  match. The raw-token decoys (`.netrc`, `.aws`, `.env`) are more robust; the
  encoding fixture uses `.netrc` for that reason.
- **Injection phrasing.** The instruction/description regexes match a fixed verb
  and noun list. Synonyms ("set aside the earlier directions"), passive voice,
  and homoglyphs step outside it.
- **Signature drift between surfaces.** The MCP metadata scanner catches the
  verb "override"; the skill instruction scanner does not. The two lists have
  diverged.
- **Write-to-file exfiltration.** The decoy scan reads stdout and stderr, not
  the sandbox filesystem, so a script that stages a secret to a file and prints
  nothing is unseen — though the writable home was furnished to make a
  post-run diff possible.

## Expectation classes

Not every planted item should become a *finding*. detonate deliberately
separates two things, and the manifest records which is expected with `expect:`:

- **`finding`** — critical or notable; drives the verdict.
- **`observation`** — informational context for a reviewer. Capability signals
  like "uses shell" or "references an API key" are *not* findings, because
  flagging them is what made earlier revisions report 30/59 honest skills as
  suspicious.

## These fixtures are inert

Written to be caught, not to work:

- Credential reads target only the **planted decoys** inside the sandbox home,
  whose contents are per-run nonces, not real secrets.
- Network egress targets `.invalid` (RFC 2606 reserved, resolves nowhere) and
  the sandbox denies egress regardless.
- Destructive commands appear **only as instruction text** for the analyser to
  read. No script here deletes anything.

They still run only inside the sandbox: network off, read-only root, non-root,
all capabilities dropped.

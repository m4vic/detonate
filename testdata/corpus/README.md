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
| `evil-mcp-encoding` | MCP | 8 / 9 | credential-exfil **encoding** robustness, and the SSH decoy's derived value |
| `evil-mcp-injection` | MCP | 2 / 6 | description-injection **phrasing** robustness |
| `evil-mcp-exfil-file` | MCP | 1 / 1 | exfil staged to disk instead of returned |
| `evil-mcp-covert` | MCP | 2 / 2 | **manifest-clean** theft: honest tool names/descriptions, harm only at runtime |
| `evil-skill` | Skill | 10 / 10 | breadth: injection, permission mismatch, script exfil |
| `evil-skill-obfuscated` | Skill | 1 / 4 | skill-injection **phrasing** robustness + signature-list alignment |
| `evil-skill-exfil` | Skill | 4 / 4 | exfil **channel** robustness (encoding + write-to-file) |
| `evil-skill-covert` | Skill | 1 / 2 | **instructions-clean** skill: SKILL.md passes review, a script betrays it at runtime |

Total: **40 / 50 detected, 10 recorded gaps, 0 findings on the honest twins.**

The two `*-covert` fixtures are the ones that most directly justify the tool. A
static reviewer reading the manifest or the SKILL.md sees nothing wrong in
either: honest tool names, honest descriptions, no injection phrasing. The harm
is only in what the code does when it runs — a weather tool that also returns
your SSH key, a file reader clean on its first call and leaking on every one
after, a tidy-formatter script that folds AWS credentials into its output
disguised as a build fingerprint. detonate catches all four, which is the whole
argument for executing a target rather than reading it.

The gap count did not fall when the SSH-decoy gap closed, and that is not an
error. That gap was never one of the nine scored lines — it lived only as prose
in this file, with no fixture exercising it, which is exactly the state the
workflow above warns about. Closing it added three *caught* lines rather than
removing a gap: 34/43 became 37/46.

The honest twins already in the repo — `testdata/honest` and
`testdata/benign-formatter` — are the control, and `TestCorpusHonestTwinsStay
Quiet` fails if either produces a finding. Without them a scanner that flags
everything would score perfectly above.

## Gaps this corpus has surfaced

Recorded, not hidden — an evasion nobody has written down is one nobody is
working on.

### Closed

- **Output-transform exfiltration (partial).** The decoy matcher now also
  checks a reversed and a rot13 encoding of the token, and scans a
  whitespace-stripped view of the output — so reversing, rot13-ing, or
  space-separating a secret no longer evades it. Safe to broaden because the
  token is a unique 64-hex-character nonce: no honest output contains its
  reverse or rot13 by chance (the honest twins confirm it). `gzip+base64`
  remains open below.
- **Signature drift between surfaces.** The skill instruction-override pattern
  was aligned with toolscan's, which already had the verb "override" (and
  `any`, `preceding`, `directions`). The same override sentence is now caught as
  both a skill instruction and an MCP description.
- **Write-to-file exfiltration.** After the target runs, the writable home is
  scanned for planted tokens sitting in files that are not the decoys
  themselves — a secret copied somewhere new. Wired into both surfaces (the
  skill script path and the MCP probe path), so staging a secret to disk instead
  of returning it no longer leaks unseen.
- **The SSH-key decoy was base64-only.** Its file holds `base64(token)`, never
  the raw token — a real OpenSSH private key body IS base64, so the decoy has
  to look like one. Any transform on top of that — even plain hex on the whole
  file — used to produce a string equal to no encoding of the bare token, and
  evaded the match. `derivedEncodings()` in `internal/decoy` now also checks
  transforms of the *derived* value (`base64(token)`) for this decoy
  specifically. The raw-token decoys (`.netrc`, `.aws`, `.env`) never had this
  problem, which is why the general encoding-boundary fixture still uses
  `.netrc`; three new tools (`read_ssh_hex`/`_reversed`/`_rot13`) were added
  to `evil-mcp-encoding` specifically to exercise this decoy under the real
  pipeline, not just a decoy-package unit test.

### Open

- **Compressed exfiltration.** `gzip+base64` (and any encoding that isn't a
  static transform of the token) still evades the matcher — catching it means
  attempting decompression of blobs in the output, not adding one more encoding.
- **Injection phrasing.** The instruction/description regexes match a fixed verb
  and noun list. Synonyms ("set aside the earlier directions"), passive voice,
  homoglyphs, and base64-with-a-decode-nudge step outside it.
- **Persistence writes leave no token.** The whole decoy design keys on planted
  nonces: a leak is proven because a value that existed nowhere else came back.
  A script that establishes persistence — appending a `curl | sh` implant to
  `~/.bashrc`, dropping a cron entry — writes attacker-controlled *code*, not a
  token, to a file that holds no decoy, so nothing matches. Catching it means
  watching sensitive startup paths for writes, a different mechanism from the
  token match. Planted in `evil-skill-covert` as `covert.persistence-no-token`.

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

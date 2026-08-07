# detonate — current status

Verified 2026-08-05 against `origin/main` (`5c5aa38`) and `v0.1.0`. This file
states ground truth, checked, not aspiration. If it disagrees with the code,
the code is right and this file is stale — fix it in the same PR that changes
behavior.

## The one-line answer

**`go install` works. Nothing else does yet.** `v0.1.0` is tagged and
`go install github.com/m4vic/detonate/cmd/detonate@v0.1.0` installs and runs —
verified today from a clean `GOBIN`. But the release workflow that should have
attached five platform binaries and `checksums.txt` produced **zero** assets;
every download URL 404s. A Go developer can install this tool. Nobody else
can yet.

## Branches — less alarming than it looks

Five branches exist, but only two carry real unmerged work:

| Branch | State |
|---|---|
| `main` | Builds clean, `go vet` clean, tagged `v0.1.0` |
| `docs/research-plan` | **0 commits ahead of main** — fully merged, safe to delete |
| `release/r0-reproducible-alpha` | **0 commits ahead of main** — fully merged, safe to delete |
| `feat/demo-fixtures` | **1 commit ahead** — a matched vulnerable/benign MCP server pair, not yet merged |
| `feat/quality-lens` | **2 commits ahead** — the design/cost analysis feature, not yet merged |

Action: delete the two merged branches from GitHub's UI (they add nothing,
they just make the branch list look worse than the repo's actual state). Open
PRs for the other two and merge them — both build clean and pass their own
tests independently.

## What is actually verified working today

Checked by running the real binary against real targets this session, not by
reading the code and assuming:

- Static analysis of skills and prompts — no Docker, seconds. Ran against
  `anthropics/skills` (docx, 15 bundled scripts) with a correct result.
- Dynamic MCP scanning — sandboxed, probed. Ran against
  `modelcontextprotocol/servers` (`everything`, `filesystem`) and against
  the project's own fixture pair.
- The evidence claim on the README is real: a deliberately vulnerable fixture
  server returns actual `/etc/passwd` content through a path-traversal probe;
  its safe twin, same tool, same description, returns nothing. Exit 3 and
  exit 0 respectively, confirmed today.
- `detonate doctor` correctly reports Docker readiness and image presence.
- Monorepo detection: pasting a repository of packages
  (`modelcontextprotocol/servers`) now lists every scannable package with the
  exact `--path` command, instead of dead-ending with "no recognisable entry
  point."
- Design/cost analysis (`feat/quality-lens`, unmerged): reports token cost per
  tool/skill and design notes (missing descriptions, undeclared annotations),
  strictly separated from the security verdict — verified never to change an
  exit code or appear in JSON/SARIF output.

## What is broken or missing, specifically

**Release binaries — broken, blocking, unexplained.** The `verify` job in
`.github/workflows/release.yml` gates `build`; `build` never ran, so `verify`
failed on the `v0.1.0` tag. Every local reproduction of `verify`'s steps
(`gofmt`, `go vet`, entrypoint tracking) passes on this machine. The one step
not reproducible here is `go test -race`, which requires `CGO_ENABLED=1` and
this Windows machine has no C toolchain — the workflow runs on
`ubuntu-latest`, where cgo is available, so this is not necessarily the cause,
only the one step nobody has confirmed passing. **The actual cause is only
visible in the GitHub Actions log for the `v0.1.0` run, which nothing in this
session can read.** Check it, paste the failing step, and it gets fixed and
re-tagged as `v0.1.1` same day.

**No package manager install.** Homebrew formula and Scoop manifest exist in
`packaging/`, complete except for placeholder SHA-256 values, but no tap or
bucket repository has been created. Blocked on binaries existing to hash.

**Acquisition still runs target-controlled hooks as root with network
access**, before the hardened sandbox engages. Documented honestly in the
README's Honest Limitations section. This is the reason detonate should not
yet be promoted as safe to point at genuinely untrusted code — only at
targets the user already has some reason to trust, same as running any
unreviewed `npm install`.

**`trace.Event` has no `seq` field.** Immaterial to a standalone detonate
release, but material to `v1.0`: the report schema freezes at `v1.0`, and a
sibling project (ASRT) needs to cite `trace_seq` in its own evidence contract
and cannot once that freeze happens. Cheap now, a breaking change later.

**No CI job runs the fixture pair.** `feat/demo-fixtures` ships a vulnerable
server and its safe twin specifically so a false positive or false negative
is machine-checkable, and nothing currently asserts on either exit code in
CI. The regression gate that matters most is built and sitting unused.

## Should this be pushed to GitHub right now

It already is — `main` has been public since before this session, and
`v0.1.0` is a real, resolvable, `go install`-able tag. The open question isn't
whether to push; `main` is already the correct thing for a Go developer to
find. It's whether to **promote** it — put it in a README badge, post it
somewhere, point non-Go users at it — and the honest answer there is not yet,
specifically because of the binaries gap above. A stranger without Go who
follows today's README install instructions hits five consecutive 404s.

## Immediate next steps, in order

1. Open the Actions log for the `v0.1.0` release run; find the actual failing
   step. Paste it here for a same-day fix, or fix and re-tag directly.
2. Merge `feat/demo-fixtures` and `feat/quality-lens` — both are independently
   verified working and there is no reason they are still sitting open.
3. Delete `docs/research-plan` and `release/r0-reproducible-alpha` — fully
   merged, contributing nothing but branch-list noise.
4. Re-tag once binaries exist and download-check clean, e.g. `v0.1.1`.
5. Then, only then, update the README's install section to point at the
   binaries and consider the tool promotable to a non-Go audience.

See [PRODUCTION_GRADE.md](PRODUCTION_GRADE.md) for the gap to a 1.0 a
maintainer would put their name behind unattended.

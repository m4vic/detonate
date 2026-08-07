# detonate — gap to production grade

Written 2026-08-05. Companion to [STATUS.md](STATUS.md), which says where
things stand right now; this says what "done" means and orders the remaining
work. The bar used throughout: **would a maintainer accept ownership of a
bad result from this tool at 3am** — not "does it run," which `v0.1.0`
already answers yes to.

Grades are cumulative. Everything under MVP is a precondition for Production,
not a separate track.

## MVP grade — passes

| # | Item | Status |
|---|---|---|
| 1 | Core action works end to end on real input | ✅ verified against live MCP servers and skills this session |
| 2 | The first real error a user hits is visible | ✅ structured phase/code/message, never a silent hang |
| 3 | The boundary of what it doesn't do is stated | ✅ README's Honest Limitations is unusually direct about this |
| 4 | An outsider can run it from the README alone | ⚠️ true for a Go developer; false for anyone else until binaries exist |
| 5 | Any signal at all that it's broken | ✅ exit codes 0/1/2/3/4 mean distinct things, deliberately |
| 6 | Failures in an external system are catchable before they propagate | ✅ every pipeline phase attributes its own failure |

MVP passes with one asterisk, and the asterisk is the whole first section of
this document.

## Production grade — item by item

### 1. Installable by someone who is not a Go developer

**Status: failing.** This is the top priority stated repeatedly and it is
also the one concretely broken thing right now. `go install` works; the
release binaries that would let a `curl | tar` user or a Homebrew/Scoop user
install it do not exist, because the release workflow's `verify` job failed
on the `v0.1.0` tag and its cause is unread. See STATUS.md for the full
account. Nothing else on this list matters to a non-Go user until this is
fixed.

**Definition of done:** `v0.1.1` (or whatever tag follows the fix) has six
assets attached — five platform binaries and `checksums.txt` — each
downloadable, each producing a working binary that reports the correct
version.

### 2. A trustworthy, checked release process

**Status: partially failing — the check that would have caught #1 exists but
was never run.** `.github/workflows/release.yml` is well-designed: it gates
binary publication on tests passing, cross-compiles five targets from one Go
toolchain, and generates checksums. The gap isn't the design, it's that the
first real run of it silently failed closed with no one watching, which is
exactly the failure mode a solo maintainer has to defend against — nobody
else is going to notice for you.

**Definition of done:** the next tag either succeeds or fails loudly somewhere
a human sees it same-day. A calendar reminder to check Actions after tagging
is an acceptable fix at this scale; a Slack webhook on workflow failure is a
better one and costs about ten minutes to add.

### 3. Acquisition does not run untrusted code as root with network access

**Status: known, documented, unfixed. The correct 1.0 blocker.**

Every other security property detonate claims (sandboxed detonation, no
network at probe time, evidence over assertion) is real and demonstrated. This
one thing is not: `pip install` / `npm install` runs during acquisition with
network on and as root, before the hardened sandbox ever engages. The README
says so, in the open, which is the right way to carry a known gap — but it
means detonate cannot honestly be promoted as "safe to point at anything." It
is safe to point at things you already have some baseline trust in, the same
bar as running `npm install` on a dependency you chose to add.

**Definition of done:** acquisition either drops root, drops network, or both
— sequenced as its own piece of work, not bundled into this release. Track
separately; do not let it block the binaries fix above, which is unrelated
and higher urgency.

### 4. The regression gate you already built is not wired to anything

**Status: failing, cheap to fix.** `feat/demo-fixtures` ships a matched
vulnerable/benign MCP server pair specifically so a false positive or false
negative becomes a machine-checkable fact instead of a manual spot-check. No
CI job asserts on it. This is the single highest-value-per-hour item in this
document: the test already exists, it just isn't run automatically.

**Definition of done:** a CI job scans both fixtures on every PR and fails if
the vulnerable server doesn't exit 3 or the benign one doesn't exit 0.

### 5. Design/cost analysis is correct but sitting on a branch

**Status: done, unmerged.** `feat/quality-lens` was built and verified this
session: it reports token cost and design notes for both MCP servers and
skills, confirmed never to change an exit code, never to appear in
machine-readable output, and to produce zero warnings on well-built input
(tested explicitly, because a lens that scores good input as faulty gets
switched off). This is also the feature that answers the "maker perspective"
half of what you're asking detonate to be — nothing new needs building here,
it needs merging.

**Definition of done:** merged to `main`.

### 6. The report schema has no stable event identifier

**Status: not yet material to detonate alone; material before 1.0.**
`trace.Event` has no `seq` field. Irrelevant to running detonate standalone
today. Relevant because the report schema freezes at `v1.0` per the existing
roadmap, and a sibling project's evidence contract needs to cite a specific
trace event by a stable ID — adding it after the freeze is a breaking change,
adding it before is not.

**Definition of done:** a monotonic `seq` on every `trace.Event`, before the
`v1.0` schema freeze, not after.

### 7. Branch hygiene

**Status: cosmetic, but visible.** Two of the five branches are fully merged
and contribute nothing but the appearance of unfinished work. This is the
"five branches" observation — the fix is deleting two branches, not a
structural problem with the project.

**Definition of done:** `docs/research-plan` and
`release/r0-reproducible-alpha` deleted; `feat/demo-fixtures` and
`feat/quality-lens` merged or closed.

## What is explicitly not on this list, and why

**An LLM anywhere in the verdict path.** The README's strongest claim is that
no model is involved in any finding, which is what makes an exit code
reproducible and safe to gate CI on. An opt-in, clearly-labeled LLM
*explanation* layer that cannot alter a finding is a legitimate future
feature; an LLM that decides or phrases what counts as a finding would
undercut the thing that differentiates this tool from every competitor that
already does that.

**A paid tier inside this repository.** Already decided and settled: this
project's job is adoption and trust-building, not revenue, and Apache-2.0
with no CLA is the right shape for that. Revisiting this is not a production-
grade question and doesn't belong on this list.

**Uptime, alerting, on-call rotation, backup/restore.** This is a local CLI a
person runs on demand, not a hosted service. Importing service-shaped
production checklists here would be checking boxes that describe a different
kind of system, not adding real rigor.

## Order

1. Read the Actions log, fix the release, re-tag with working binaries — the
   one thing actually blocking the stated top priority.
2. Wire the fixture pair into CI — cheapest real gate available.
3. Merge `feat/quality-lens` and `feat/demo-fixtures`; delete the two dead
   branches.
4. Add `seq` to `trace.Event` — small, and the window to do it cheaply is
   closing at `v1.0`.
5. Acquisition hardening — real, scoped work, sequenced last because it is
   the only item here that isn't quick and isn't currently blocking anything
   else.

Steps 1 through 3 are hours, not days. Step 4 is under an hour. Step 5 is the
only genuinely open-ended item, and it should be scoped and planned on its
own once the first four are done.

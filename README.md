# detonate

**Test your MCP server or Agent Skill before you publish it.**

Detonate runs your target in a locked sandbox, plants fake credentials where a
thief would look, and reports what it actually did — with a CI-gateable exit
code and SARIF for the GitHub Security tab.

<p align="center">
  <img src="docs/assets/dynamic-mcpb-scan.png" width="820" alt="Detonate dynamically scans a public MCPB server: offline non-root sandbox launch, tool discovery, honest partial coverage, and a saved report bundle">
</p>

<p align="center">
  <img src="https://img.shields.io/github/license/m4vic/detonate" alt="License">
  <a href="https://github.com/m4vic/detonate/stargazers"><img src="https://img.shields.io/github/stars/m4vic/detonate" alt="Stars"></a>
  <img src="https://img.shields.io/github/v/tag/m4vic/detonate" alt="Version">
  <img src="https://img.shields.io/github/last-commit/m4vic/detonate" alt="Last Commit">
</p>

> **`0.x` software.** It installs, it runs, and it finds real things, but it has
> bugs, false positives, and false negatives. A `no_findings` result is **not** a
> security certification. Use disposable targets, never supply real secrets, and
> read the [disclaimer](DISCLAIMER.md) before running dynamic scans.

---

## Install

One static binary. No Python environment, no Node, no API key, and it never
calls out to a service.

**Download a binary** — Linux, macOS, or Windows — from the
[releases page](https://github.com/m4vic/detonate/releases), extract it, put it
on your `PATH`, and verify it against `checksums.txt`.

```bash
# macOS / Linux
VERSION=$(curl -sSL https://api.github.com/repos/m4vic/detonate/releases/latest | grep '"tag_name"' | head -1 | cut -d'"' -f4)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl -sSL "https://github.com/m4vic/detonate/releases/download/${VERSION}/detonate_${VERSION#v}_${OS}_${ARCH}.tar.gz" | tar xz
sudo mv detonate /usr/local/bin/
```

```bash
# With Go 1.25+ installed
go install github.com/m4vic/detonate/cmd/detonate@latest
```

```bash
# From source
git clone https://github.com/m4vic/detonate && cd detonate
go build -o detonate ./cmd/detonate
```

Then check the machine:

```bash
detonate doctor
```

**Docker is needed to execute a target, not to use detonate.** Prompt, skill,
and MCPB manifest analysis read text rather than run it, so they work with no
container runtime at all. `doctor` tells you which scans your machine supports.

| You want to scan | You need |
|---|---|
| A prompt or instruction file | nothing but detonate |
| An Agent Skill's instructions | nothing but detonate |
| An MCPB bundle's declared tools | nothing but detonate |
| A running MCP server, or a skill's bundled scripts | **Docker** |

---

## See it work in one minute

Two fixtures ship with the repo. One steals; one behaves. Both are probed
identically — that pairing is the point, because a scanner that only ever alarms
tells you nothing.

```bash
git clone https://github.com/m4vic/detonate && cd detonate
go build -o detonate ./cmd/detonate

./detonate dynamic testdata/thief  --cmd "python /target/server.py" --no-install
./detonate dynamic testdata/honest --cmd "python /target/server.py" --no-install
```

The thief:

```text
  RISK: dangerous  (2 finding(s))
  COMPLETENESS: complete

  [FINDING] 1  [CRITICAL] tool "read_file" returned the contents of /home/detonate/.ssh/id_rsa
     evidence : planted secret /home/detonate/.ssh/id_rsa returned base64-encoded
                (nonce b6b4f5d63c3d52f44d00a51c920543a6)
     observed : +4ms during probe:baseline
     source   : decoy
```

**That nonce is the whole argument.** It is 128 bits, generated for that one
run, and it exists nowhere else on earth. It came back *base64-encoded*, so the
tool read the file and re-encoded it — it was not echoing our input. There is no
benign explanation to argue about, and nothing here rests on a model's opinion.

The honest server exits **0** under the same probes, and says what it proved
rather than only reporting an absence:

```text
  RISK: no_findings
  - planted 6 credential decoys in the sandbox; none were returned by any tool
```

---

## Use it in CI

```yaml
name: detonate
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # so findings reach the Security tab

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: m4vic/detonate@v0
```

That scans on every push, fails the job on findings, and publishes SARIF so
results appear in **Security → Code scanning** and inline on pull requests. The
released binary's checksum is verified before it runs.

| Input | Default | What it does |
|---|---|---|
| `target` | `.` | Path or git URL to scan |
| `mode` | `static` | `static` never executes the target; `dynamic` runs it in a Docker sandbox |
| `version` | `latest` | Pin a release for reproducible CI |
| `fail-on` | `findings` | `findings` (exit 3), `incomplete` (also exit 4), or `never` |

### Exit codes

These are frozen. A pipeline can gate on them.

| Code | Meaning |
|---:|---|
| `0` | clean — something was assessed and nothing was found |
| `1` | the scan itself broke |
| `2` | usage or environment problem |
| `3` | findings |
| `4` | nothing was learned about the target, or `--fail-incomplete` and coverage was short |

`1` and `3` are deliberately distinct: a pipeline must be able to tell a
detonate bug from a real finding in your code.

---

## Commands

```bash
detonate static  <file|folder|git-url>    # never executes the target; no Docker
detonate dynamic <file|folder>            # runs it in a sandbox
detonate report  <bundle-dir>             # re-render a saved result offline
detonate doctor                           # check the machine

detonate static --help                    # options and exit codes for one mode
```

Useful flags: `--format json|sarif`, `--out FILE`, `--save`, `--path SUBDIR`
(for a monorepo), `--fail-incomplete`, `--cmd "…"` and `--no-install` (to scan a
server you have already built).

### Scanning a server you did not write

```bash
detonate static https://github.com/anthropics/skills --path skills/pdf
```

If detonate cannot tell what a repository is, it says so and prints the exact
commands to try — a repo of packages gets a `--path` suggestion per package.

For a pre-built server, mount it and name the command. The folder appears at
`/target` inside the sandbox:

```bash
detonate dynamic ./my-server --cmd "node /target/dist/index.js" --no-install
```

---

## What's new in 0.4.0

- **Credential decoys.** The sandbox is furnished with plausible SSH keys, cloud
  credentials, a `.env`, a `.netrc`, a GitHub token, and shell history — each
  carrying a unique 128-bit nonce. A tool that returns one has leaked a
  credential, and the nonce is printed in the evidence.
- **A bounded proven-negative.** A clean scan asserts what it proved rather than
  only reporting an absence.
- **Nested input schemas are probed.** Payloads reach strings inside arrays and
  objects, not only top-level parameters. On the official MCP memory server this
  took tools with a reachable attack surface from **3 of 11 to 10 of 11**.
- **The sandbox stops taking the blame.** A tool that fails because egress is
  denied, or because the root filesystem is read-only, is reported as
  `unsupported` naming the restriction — not as a broken tool. Accusing a
  working server of being broken is a false positive like any other.
- **A scan that assessed nothing no longer exits 0.** Four real community MCP
  servers returned `not_assessed` and exited clean; a pipeline reads `0` as
  "safe to merge". They now exit 4.
- **MCP tool-metadata analysis.** Instruction injection, concealment, tool
  shadowing, pseudo-system markup, invisible Unicode tag smuggling (decoded into
  the evidence), and bidi overrides. Deterministic, no model involved.
- **A GitHub Action**, a total scan budget (15 min default), and `--help` for
  every subcommand.

Full detail in the [changelog](CHANGELOG.md).

---

## Why not just use a static scanner

Most MCP scanners read the manifest, pattern-match the source, and ask a model
what it thinks. Detonate does that too — and then runs the thing.

| | Reads manifests and source | Executes the target and probes its tools |
|---|---|---|
| Static and LLM-based scanners | yes | no |
| **detonate** | yes | **yes** |

The distinction is not academic. Published measurement of static MCP analysis
found it scored **100% on Python and 0% on JavaScript**, while dynamic analysis
of the same corpus scored 100% across every language
([arXiv:2603.21641](https://arxiv.org/abs/2603.21641)). Detonate speaks to a
running server over the MCP protocol and never parses target source, so its
coverage does not depend on the language the target happens to be written in.

It also means a finding is a fact rather than a suspicion. The file came back or
it did not.

**No LLM is involved in any verdict.** Findings come from deterministic rules
over static artifacts and collected runtime evidence. A scanner whose output
changes between runs cannot gate a pipeline.

---

## What it checks

**MCP servers** — the danger is code that executes.

| | |
|---|---|
| Adversarial probes | path traversal, command injection, SSRF, template injection, encoding abuse, oversized input: 13 payloads across 7 [MCPTox](https://arxiv.org/pdf/2508.14925) classes |
| Credential exfiltration | planted decoys matched on the way out, plain, base64, or hex |
| Tool metadata | injection, concealment, shadowing, invisible Unicode, bidi overrides |
| Sandbox controls | egress denied, read-only root, non-root, capability/PID/memory policy |
| Rug pulls | tool-description hashes diffed against an advancing baseline |
| Pagination | follows every `tools/list` cursor with loop detection and hard ceilings |

**Skills** — mostly a large prompt, so the danger is text the agent obeys.

| | |
|---|---|
| Injection | context overrides, concealment instructions, credential access |
| Permission mismatch | declares `allowed-tools: [Read]` then instructs shell commands |
| Bundled scripts | run one-by-one in the sandbox |

**Prompts** — the same instruction analysis, on any text an agent will read.

---

## How it works

```
TARGET       clone or mount it, read-only
   |
FETCH        separate container, network ON, scripts disabled; Python accepts
             wheels only and Node VCS/local sources are rejected
   |
BUILD        network OFF, non-root
   |
DETONATE     network OFF, read-only root, all capabilities dropped,
             no-new-privileges, non-root, memory and PID caps,
             credential decoys planted in the sandbox home
   |
PROBE        call schema-reachable tools with hostile arguments, diffed
             against a benign baseline call
   |
ASSESS       independent risk + completeness over evidence and scenarios
```

Risk and completeness are kept independent on purpose. "We found nothing" and
"we could not look" are different facts, and collapsing them is how a scanner
tells you something is safe when it simply failed.

---

## Honest limitations

- **No findings is not proof of safety.** Reports separate `risk` from
  `completeness` and list every scenario outcome. Read both.
- **Tools that need the network cannot be behaviourally probed.** The sandbox
  denies egress on purpose, so a tool calling an external API is reported as
  `unsupported` naming the restriction — not as a finding.
- **Tools that need to write may not be probed either.** The root filesystem is
  read-only, so a server that persists state can fail on a valid call. Reported
  the same honest way.
- **A container is not a virtual machine.** It is a process on the host kernel
  behind namespaces and cgroups, so a kernel exploit escapes it. That is why the
  policy drops every capability, sets `no-new-privileges`, and refuses root:
  defence in depth, because the boundary is not absolute.
- **Static mode reaches roughly a third of targets.** It needs an MCPB
  `manifest.json` to read an inventory. Measured on real community servers, most
  ship none — so static mode correctly returns "not assessed" and exit 4 rather
  than a clean-looking result. Dynamic mode is the answer for those.
- **Startup and invocation are observed; syscalls are not.** eBPF-level tracing
  would close that gap and is not built.
- **Safe acquisition is intentionally conservative.** Registry-backed Node
  packages and wheel-only Python requirements are supported. Source
  distributions, recursive requirements, VCS/local Node dependencies, and
  network-dependent build hooks produce `acquisition_unsupported` rather than
  relaxing the boundary. Use `--no-install --cmd` for a pre-built server.
- **Servers that shell out to system binaries may not start.** The images are
  slim, so a server needing `git` fails on a missing executable. The error names
  the cause.

---

## Calibration

False positives are why security tools get switched off, so detectors are
measured against real, known-good targets before shipping.

| Corpus | Flagged |
|---|---|
| 59 skills from a public skill pack | 4, all verified true |
| 40 Google plugin skills | 1, verified true |
| 27 real tool descriptions from official MCPB examples | 0 |

Earlier revisions flagged 30/59 and 11/12. Both times the cause was the same:
measuring *capability* as if it were *malice*. A skill that uses an API key, or
warns you never to commit private keys, is not an attack.

False *negatives* get the same treatment. Script discovery once looked only at a
skill's top level, so Anthropic's own `docx` skill — 15 Python files under
`scripts/` — was reported as instructions only. A clean verdict on the reference
implementation of the format. An error tells you to look closer; a clean verdict
tells you not to bother.

Measured results against real targets are recorded in
[COMPATIBILITY.md](docs/COMPATIBILITY.md), including the failures.

---

## Status

`0.x`. Flags and report fields may still change within a minor version;
breaking changes are named in the [changelog](CHANGELOG.md). Exit codes are
frozen and covered by a test that fails loudly if anyone moves one.

Interfaces stabilize at `1.0` — meaning the report schema and exit codes are
final and acquisition is safe, not that every feature is built.

## Docs

- [Architecture](docs/ARCHITECTURE.md) — what the code does today, module by module
- [Plan](docs/PLAN.md) — what "done" means, and what is deliberately not being built
- [Compatibility](docs/COMPATIBILITY.md) — measured results against real targets, including what failed

## Project policies

- [Security reporting](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Support](SUPPORT.md) · [Changelog](CHANGELOG.md)

## License

Apache-2.0

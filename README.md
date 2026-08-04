# detonate

> **This project is constantly evolving and is currently not production-grade.**
> Detonate can have bugs, false
> positives, and false negatives. A `no_findings` result is not a security
> certification. Use disposable test targets, never provide real secrets, and
> read the full [disclaimer](DISCLAIMER.md) before running dynamic scans.

**Run untrusted AI tools in a sandbox and report what they actually do, not what
their manifest claims.**

You install an MCP server from GitHub. It runs on your machine, with your
permissions, and your AI assistant calls its tools automatically. Nobody reads
the code first.

Many scanners stop at manifests or source. detonate also runs supported targets
in a disposable container, calls schema-reachable tools with hostile input, and
reports the evidence it can collect.

```
detonate: discovered 1 tool(s):
    [mcp] read_file: Read the contents of a file.

  ----------------------------------------------------------------
  RISK: dangerous  (1 finding(s))
  COMPLETENESS: complete
  ----------------------------------------------------------------
  Coverage: 2/2 scenario(s) completed

  1. [CRITICAL] tool "read_file" leaked data via path-traversal
     evidence : root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin
     observed : +2ms during probe:path-traversal on read_file
     source   : probe-response
```

That is the real content of `/etc/passwd`, returned by the tool, because
detonate asked it for `../../../../etc/passwd`. The manifest said "Read the
contents of a file." A static scanner reports it clean.

## Install (not available from a clean checkout yet)

There is no working public release yet. The worktree now exposes
`cmd/detonate/main.go`, but that entrypoint is still untracked, so
`go install ...@latest` and a clean source build remain unavailable until the
changes are committed and the release gates pass. Do not publish or recommend
the commands below until the Phase 0 release blocker in the
[implementation plan](docs/IMPLEMENTATION_PLAN.md) is fixed.

Intended installation after that gate:

```text
# With Go installed
go install github.com/m4vic/detonate/cmd/detonate@latest

# Or from source
git clone https://github.com/m4vic/detonate
cd detonate
go build -o detonate ./cmd/detonate
```

Dynamic MCP/skill scans require Docker; prompt-only and future static-only
profiles do not.

## Use

The alpha CLI has three explicit modes:

```text
detonate static <target>    available: does not execute target code
detonate dynamic <target>   experimental: runs the current Docker sandbox path
detonate combined <target>  intentionally unavailable in alpha
```

Use static mode first for a file, folder, or Git URL:

```bash
detonate static ./skills/pdf-extractor
detonate static ./system-prompt.txt
detonate static github.com/owner/repo
```

Static prompt and skill analysis need no Docker. Static MCP mode currently
records only source/manifest inventory and reports incomplete coverage; it does
not claim an MCP security verdict until source analysis is implemented.

Dynamic mode is explicit because it can execute untrusted code inside Docker:

```bash
detonate dynamic ./my-server           # MCP server
detonate dynamic ./skills/pdf-extractor # agent skill
```

detonate works out what the target is. A folder with a `SKILL.md` is a skill,
a folder with an entry point is an MCP server, a `.txt` or `.md` file is a
prompt.

A package inside a monorepo is reached with `--path`:

```bash
detonate github.com/modelcontextprotocol/servers --path src/memory
```

The entry point comes from the manifest, so servers with no runnable file on
disk are handled: `bin`/`main` for Node, `[project.scripts]` for Python.
TypeScript projects whose `dist/` is generated at publish time are compiled
first, in the install container — including monorepo packages, whose build
needs the config they inherit from the repository root.

Or run it with no arguments for the slash-command interface:

```
detonate
detonate> /static ./system-prompt.txt
detonate> /dynamic ./my-server
detonate> /help
```

Entering a target without a slash uses static mode. Dynamic mode remains
experimental: dependency and build hooks may run as root in the networked
acquisition container. Schema-reachable tools are called with adversarial
input, and discovered skill scripts are executed without dependency-aware
invocation data. `--quick` opts out of dynamic stages.

If detection guesses the start command wrong:

```bash
detonate ./weird-server --cmd "python /target/main.py"
```

Inside the sandbox your folder is mounted at `/target`, which is why `--cmd`
uses that path rather than a host one.

**Exit codes:** `0` completed without a gated issue, `1` error, `2` bad usage
or environment, `3` findings, `4` incomplete coverage when
`--fail-incomplete` is enabled.

### In CI

`--format sarif` produces output GitHub code scanning understands, so findings
appear as annotations on the pull request diff.

```yaml
- name: Scan agent dependencies
  run: detonate ./mcp-servers/my-server --fail-incomplete --format sarif --out detonate.sarif
  continue-on-error: true          # let the upload run, then gate on it

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: detonate.sarif
```

`--format json` gives the same scan as structured data for anything else.
Exit codes are identical across formats, so switching to SARIF for
annotations cannot change whether the build passes.

Failures before or during execution still emit the requested JSON/SARIF
document. JSON reports place them in `failures` with a stable `phase`, `code`,
bounded `message`, and `retryable` flag; the failed phase also appears in
`scenarios`, so risk remains `not_assessed` rather than becoming a false clean
result. Current codes are:

| Code | Phase |
|---|---|
| `fetch_failed` | repository fetch |
| `runtime_unavailable` | Docker preflight |
| `acquisition_failed` | dependency/build acquisition |
| `mcp_start_failed` | sandboxed server startup |
| `mcp_inventory_failed` | MCP negotiation or tool inventory |
| `skill_load_failed` | skill resolution |
| `scan_failed` | internal execution fallback |

## What it checks

**MCP servers** - the danger is code that executes.

| | |
|---|---|
| Adversarial probes | path traversal, command injection, SSRF, template injection, encoding abuse, oversized input: 13 payloads across 7 [MCPTox](https://arxiv.org/pdf/2508.14925) classes |
| Returned/runtime hints | returned content plus target-controlled stderr signatures |
| Sandbox controls | egress denied, read-only root, non-root runtime, capability/PID/memory policy; Docker lifecycle events are not yet wired into verdicts |
| Install time | stdout/stderr signatures from `pip install` / `npm install`; not full network/process/filesystem observation |
| Rug pulls | tool-description hashes diffed against an automatically advanced baseline; explicit approval/history is planned |
| Tool results | text, non-text content blocks, structured content, and `isError` are preserved for deterministic inspection; transcript persistence is not yet implemented |
| Pagination | follows every `tools/list` cursor with loop detection and hard page/item ceilings |

**Skills** - mostly a large prompt, so the danger is text the agent obeys.

| | |
|---|---|
| Injection | context overrides, concealment instructions, credential access |
| Permission mismatch | declares `allowed-tools: [Read]` then instructs shell commands |
| Bundled scripts | run one-by-one in the sandbox; dependencies, valid arguments, exit/timeout coverage, and helper-vs-entrypoint classification are incomplete |

**Prompts** - the same instruction analysis, on any text an agent will read.

## How it works

```
TARGET             clone or mount it, read-only
    |
ACQUIRE            separate container, network ON; dependency/build hooks may
                   execute target-controlled code as root in that container
    |
DETONATE           network OFF, read-only root, all capabilities dropped,
                   no-new-privileges, non-root, memory and PID caps
    |
PROBE              call schema-reachable tools with hostile arguments, diffed
                   against a benign baseline call
    |
ASSESS             independent risk + completeness over evidence and scenarios
```

**No LLM is involved in any current verdict.** Findings come from deterministic
rules over static artifacts and collected runtime evidence. A scanner whose
output changes between runs cannot gate a CI pipeline.

## Honest limitations

- **Acquisition is not yet a safe build boundary.** `pip install`, npm lifecycle
  scripts, and `npm run build` can execute target-controlled code while the
  acquisition container has network access, a writable root, and uid 0.
  Current install observation analyzes process output; it is not complete
  network, process, or filesystem tracing.
- **A container is not a virtual machine.** It is a process on the host kernel
  behind namespaces and cgroups, so a kernel exploit escapes it. That is why the
  detonation policy drops every capability, sets `no-new-privileges`, and
  refuses to run as root: defence in depth, because the boundary is not
  absolute.
- **No findings is not proof of safety.** Successful prompt, skill, and MCP
  reports separate `risk` from `completeness` and list every modeled scenario
  outcome. Early fetch, runtime, acquisition, startup, and inventory failures
  now produce structured reports, but the current probe set reaches only part
  of many schemas. Treat results as prototype evidence, not certification.
- **Tools that need the network cannot be behaviourally probed.** The sandbox
  denies egress on purpose, so a tool that calls an external API (Notion, Slack,
  a database) fails its probe with a resolver error. This is reported as an
  `unsupported` scenario naming which tools need egress, not as a finding —
  the sandbox working is not a defect in the tool.
- **Startup and invocation are observed; syscalls are not.** eBPF-level tracing
  would close that gap and is not built.
- **Docker is required** for everything except prompt files.
- **Servers that shell out to system binaries may not start.** The sandbox
  images are slim, so `mcp-server-git` fails on a missing `git` executable. The
  error names the cause, but the scan does not complete.
- **Monorepo packages that rely on hoisted workspace dependencies still fail.**
  Packages that inherit only a tsconfig are handled; ones that need the root
  `node_modules` are not.

## Calibration

False positives are why security tools get switched off, so detectors are
measured against real, known-good targets before shipping:

| Corpus | Flagged |
|---|---|
| 59 skills from a public skill pack | 4, all verified true |
| 40 Google plugin skills | 1, verified true |

Earlier revisions flagged 30/59 and 11/12. Both times the cause was the same:
measuring *capability* as if it were *malice*. A skill that uses an API key, or
one that warns you never to commit private keys, is not an attack.

False *negatives* get the same treatment, and one was worse. Script discovery
only looked at a skill's top level, so Anthropic's own `docx` skill — 15 Python
files under `scripts/` — was reported as **0 bundled scripts, instructions
only**. A clean verdict on the reference implementation of the format. An error
tells you to look closer; a clean verdict tells you not to bother.

Several known wrong answers came from broad text matchers, including matchers
over stderr produced by scripts running inside the sandbox. Sandbox enforcement
and runtime observation are different guarantees: the former limits a process;
the latter is currently incomplete and must be reflected in coverage.

## Status

Prototype, not release-ready. The CLI entrypoint is no longer hidden by
`.gitignore`, but remains untracked until these worktree changes are committed.
The worktree now also contains clean-archive CI for Linux, macOS, and Windows
and a release verification dependency; neither protects the public repository
until it is reviewed and committed.
Successful scan reports now expose risk, completeness, and scenario coverage;
common early pipeline failures now preserve that contract, while validation,
cancellation, teardown, and several runtime evidence gaps remain. See the
reviewed architecture, implementation plan, and compatibility record below.
Interfaces may still change.

## Design and roadmap

The current implementation, target architecture, and verified compatibility
results are tracked separately so proposed features are not mistaken for
shipped behavior:

- [Architecture](docs/ARCHITECTURE.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Production-readiness and launch plan](docs/PRODUCTION_READINESS.md)
- [Compatibility and live tests](docs/COMPATIBILITY.md)

## Project policies

- [Security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Changelog](CHANGELOG.md)

## License

Apache-2.0

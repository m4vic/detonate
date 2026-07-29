# detonate

**Run untrusted AI tools in a sandbox and report what they actually do, not what
their manifest claims.**

You install an MCP server from GitHub. It runs on your machine, with your
permissions, and your AI assistant calls its tools automatically. Nobody reads
the code first.

Every other scanner *reads* the manifest. detonate *runs* the thing in a
disposable container, calls its tools with hostile input, and reports what
happened, with evidence.

```
detonate: discovered 1 tool(s):
    [mcp] read_file: Read the contents of a file.

  ----------------------------------------------------------------
  VERDICT: dangerous  (1 finding(s))
  ----------------------------------------------------------------

  1. [CRITICAL] tool "read_file" leaked data via path-traversal
     evidence : root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin
     observed : +2ms during probe:path-traversal on read_file
     source   : probe-response
```

That is the real content of `/etc/passwd`, returned by the tool, because
detonate asked it for `../../../../etc/passwd`. The manifest said "Read the
contents of a file." A static scanner reports it clean.

## Install

Requires [Docker](https://docs.docker.com/get-docker/) for the sandbox, and
Go 1.25+ to build.

```
go install github.com/m4vic/detonate/cmd/detonate@latest
```

Or from source:

```
git clone https://github.com/m4vic/detonate
cd detonate
go build -o detonate ./cmd/detonate
```

## Use

Point it at a thing:

```bash
detonate ./my-server                  # MCP server
detonate ./skills/pdf-extractor       # agent skill
detonate ./system-prompt.txt          # prompt (no Docker needed)
detonate github.com/owner/repo        # clone and scan
```

detonate works out what the target is. A folder with a `SKILL.md` is a skill,
a folder with an entry point is an MCP server, a `.txt` or `.md` file is a
prompt.

Or run it with no arguments for a guided scan:

```
detonate
```

**Scans are thorough by default.** Dependencies are installed in a separate
container that never runs the target, tools are called with adversarial input,
and a skill's bundled scripts are executed in the sandbox. `--quick` opts out.

If detection guesses the start command wrong:

```bash
detonate ./weird-server --cmd "python /target/main.py"
```

Inside the sandbox your folder is mounted at `/target`, which is why `--cmd`
uses that path rather than a host one.

**Exit codes:** `0` clean, `1` error, `2` bad usage or environment, `3` findings.

## What it checks

**MCP servers** - the danger is code that executes.

| | |
|---|---|
| Adversarial probes | path traversal, command injection, SSRF, template injection, encoding abuse, oversized input: 13 payloads across 7 [MCPTox](https://arxiv.org/pdf/2508.14925) classes |
| Behaviour | network attempts, denied writes, process limits, OOM kills, sensitive-path reads |
| Install time | what runs during `pip install` / `npm install`, which is where supply-chain payloads live |
| Rug pulls | tool descriptions hashed and diffed against the previous scan |

**Skills** - mostly a large prompt, so the danger is text the agent obeys.

| | |
|---|---|
| Injection | context overrides, concealment instructions, credential access |
| Permission mismatch | declares `allowed-tools: [Read]` then instructs shell commands |
| Bundled scripts | run in the sandbox and watched |

**Prompts** - the same instruction analysis, on any text an agent will read.

## How it works

```
--git / --dir      clone or mount the target, read-only
    |
ACQUIRE            separate container, network ON, target NOT executed
                   install scripts observed
    |
DETONATE           network OFF, read-only root, all capabilities dropped,
                   no-new-privileges, non-root, memory and PID caps
    |
PROBE              call every tool with hostile arguments, diffed against
                   a benign baseline call
    |
VERDICT            deterministic rules over observed facts, with evidence
```

**No LLM is involved in any verdict.** Every finding comes from deterministic
rules over things that were observed. A scanner whose output changes between
runs cannot gate a CI pipeline.

## Honest limitations

- **A container is not a virtual machine.** It is a process on the host kernel
  behind namespaces and cgroups, so a kernel exploit escapes it. That is why the
  policy drops every capability, sets `no-new-privileges`, and refuses to run as
  root: defence in depth, because the boundary is not absolute.
- **A clean verdict is not proof of safety.** A target that swallows its own
  errors leaves no trace, and probes only reach tools with string parameters.
- **Startup and invocation are observed; syscalls are not.** eBPF-level tracing
  would close that gap and is not built.
- **Docker is required** for everything except `--prompt`.

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

## Status

Working and useful. Interfaces may still change.

## License

Apache-2.0

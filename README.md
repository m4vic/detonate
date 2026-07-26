# detonate

**Detonate untrusted MCP servers in a sandbox and report what they actually do,
not what their manifest claims.**

Most MCP/skill scanners *read* a tool's manifest and pattern-match its source.
detonate *runs* the tool inside a disposable sandbox and watches its real
behavior — the network it reaches for, the files it touches, the processes it
spawns. A manifest describes intent; behavior reveals reality.

> **Status: pre-alpha (M0).** The CLI and the safety pre-flight work today. The
> sandbox detonation pipeline is being built milestone by milestone — see
> [ARCHITECTURE.md](ARCHITECTURE.md) for the map and current status.

---

## Requirements

- **Python 3.10+**
- **Docker, installed and running.** detonate executes untrusted code, so it
  refuses to run without a sandbox. This is a hard requirement, not optional —
  `pip install detonate` is not enough on its own; the Docker daemon must be up.

---

## Install

```bash
pip install detonate        # once released
```

Or run from source while it's pre-alpha:

```bash
git clone https://github.com/m4vic/detonate
cd detonate
PYTHONPATH=src python -m detonate --help
```

---

## Usage

```bash
# Scan an MCP server (launched over stdio) by detonating it in a sandbox
detonate scan --mcp "uvx some-mcp-server"
```

If Docker isn't ready, detonate stops before doing anything and tells you why:

```
[detonate] cannot scan: docker binary not found on PATH
[detonate] detonate requires Docker to sandbox untrusted code. ...
```

---

## Why this exists

The AI agent supply chain has the same problem the npm/PyPI ecosystems have: you
install a tool, and it runs with your agent's full privileges — its files, its
tokens, its ability to act. Published research puts prompt injection in ~36% of
agent skills and exploitable flaws in ~30% of deployed MCP servers. The existing
scanners mostly read manifests; the one that executes tells you to sandbox it
yourself. detonate sandboxes by default and probes adversarially.

---

## License

Apache-2.0.

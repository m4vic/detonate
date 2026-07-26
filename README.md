# detonate

**Detonate untrusted MCP servers in a sandbox and report what they actually do,
not what their manifest claims.**

Most MCP/skill scanners *read* a tool's manifest and pattern-match its source.
detonate *runs* the tool inside a disposable sandbox and watches its real
behavior — the network it reaches for, the files it touches, the processes it
spawns. A manifest describes intent; behavior reveals reality.

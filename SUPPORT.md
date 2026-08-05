# Support

Detonate is currently prerelease software. There is no paid support or uptime
service-level agreement.

Use:

- a bug report when Detonate crashes, hangs, leaks a container, produces an
  invalid report, or violates a documented boundary;
- a compatibility report when an MCP server or Agent Skill cannot be acquired,
  started, negotiated with, or meaningfully tested;
- a feature request for a new transport, runtime, report integration, or
  workflow.

Before filing, collect:

```text
detonate --version
go version
docker version
```

Include the target's immutable version or commit, the exact command with secrets
removed, operating system, exit code, and the smallest safe log excerpt. Never
post API keys, tokens, private prompts, or proprietary target source.

Security vulnerabilities must use the private process in
[SECURITY.md](SECURITY.md).


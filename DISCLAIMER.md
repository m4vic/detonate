# Disclaimer

This project is constantly evolving. Detonate is experimental prerelease
software and is **currently not production-grade**.
It is provided for research, development, and controlled local/CI testing of
MCP servers, Agent Skills, and prompts.

Do not treat a Detonate result as a security certification, a guarantee that a
target is safe, or a replacement for code review, dependency review, sandbox
hardening, or professional security testing. The scanner can produce false
positives and false negatives, and a `no_findings` result does not prove that a
target is safe.

Dynamic scanning executes target-controlled code. Use disposable test targets,
avoid real credentials and sensitive data, and review the acquisition and
sandbox limitations before running an untrusted target. Docker is a defense-in-
depth boundary, not a virtual machine or an absolute security guarantee.

The project may change its CLI, report schema, supported runtimes, and security
behavior without compatibility guarantees before a stable release. Use it at
your own risk and verify every result before making a security or deployment
decision.

See [SECURITY.md](SECURITY.md), [SUPPORT.md](SUPPORT.md), and the
[production-readiness plan](docs/PRODUCTION_READINESS.md) for reporting,
limitations, and release gates.

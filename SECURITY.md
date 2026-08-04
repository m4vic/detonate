# Security policy

Detonate executes untrusted MCP servers and skill scripts. A vulnerability in
its isolation, acquisition, evidence, or reporting path can therefore have a
higher impact than a normal CLI defect.

## Supported versions

Before the first stable release, security fixes are made only on the default
branch and the newest published prerelease. Older prereleases are unsupported.

## Report a vulnerability

Use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Include the affected commit or version, host operating system, Docker
   version, target type, reproduction steps, and expected impact.

Do not open a public issue for an unpatched sandbox escape, host-code execution,
credential exposure, report forgery, or release-supply-chain vulnerability.
Do not attach real credentials or other people's private targets. A minimized
fixture is strongly preferred.

If private vulnerability reporting is unavailable, open a public issue that
contains no exploit details and asks the maintainer to establish a private
channel.

## Response expectations

The project aims to acknowledge a report within three business days, provide an
initial assessment within seven business days, and coordinate disclosure after
a fix is available. These are targets, not a service-level agreement.

## Security boundaries

The current security guarantees and known gaps are documented in
[the architecture](docs/ARCHITECTURE.md) and
[compatibility notes](docs/COMPATIBILITY.md). In particular:

- Docker is a required isolation boundary for dynamic MCP and skill execution.
- Dependency acquisition may execute target-controlled package/build hooks.
- Prompt-only static analysis does not execute code and does not require Docker.
- A no-findings result is not proof of safety; completeness must be inspected.


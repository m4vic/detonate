# Detonate design documents

These documents are the canonical design and delivery record for Detonate.
They distinguish implemented behavior from proposed behavior and must change in
the same pull request as any architectural change.

- [ARCHITECTURE.md](ARCHITECTURE.md) defines the target architecture, trust
  boundaries, result model, and non-negotiable safety properties.
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) turns that architecture into
  ordered, testable delivery phases.
- [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) defines the release trains,
  CLI contract, production gates, distribution, and promotion plan.
- [COMPATIBILITY.md](COMPATIBILITY.md) records verified behavior against real
  MCP servers, Agent Skills, prompts, and LLM providers.

The files under `../../detonate-docs-local/` are working notes and historical
material. They are not a source of truth for shipped capability.

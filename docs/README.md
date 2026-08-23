# Detonate design documents

These documents are the canonical design and delivery record for Detonate.
They distinguish implemented behavior from proposed behavior and must change in
the same pull request as any architectural change.

Read whichever answers your question and stop there.

| Question | Document |
|---|---|
| What does the code do, and what is each module for? | [ARCHITECTURE.md](ARCHITECTURE.md) |
| What ships in v0.4, and why not v0.3? | [ROADMAP.md](archive/ROADMAP.md) |
| What should I work on next? | [TASKS.md](archive/TASKS.md) |
| What are we building toward? | [TARGET_ARCHITECTURE.md](archive/TARGET_ARCHITECTURE.md) |
| Why does the canary and benchmark work exist? | [RESEARCH_PLAN.md](archive/RESEARCH_PLAN.md) |
| How is a phase delivered and gated? | [IMPLEMENTATION_PLAN.md](archive/IMPLEMENTATION_PLAN.md) |
| What must be true before release? | [PRODUCTION_READINESS.md](archive/PRODUCTION_READINESS.md) |
| What actually works against real targets? | [COMPATIBILITY.md](COMPATIBILITY.md) |
| How is one test case specified? | [TEST_SCENARIO_PLAN.md](archive/TEST_SCENARIO_PLAN.md) |

Two documents describe architecture and they are not interchangeable.
[ARCHITECTURE.md](ARCHITECTURE.md) describes the code as it exists; if it
disagrees with the source, the document is wrong.
[TARGET_ARCHITECTURE.md](archive/TARGET_ARCHITECTURE.md) describes the design being
built toward and is expected to describe things that do not exist yet.

The files under `../../detonate-docs-local/` are working notes and historical
material. They are not a source of truth for shipped capability.

# Action fixtures

Two MCPB bundles used by `.github/workflows/action-test.yml` to prove
[`action.yml`](../../action.yml) actually works before anyone is told to depend
on it: one that must pass, one that must fail.

They are deliberately minimal — the point is the action's plumbing (download,
checksum, run, SARIF, exit code, gating), not detection breadth. Detection is
covered by the unit tests in `internal/toolscan`.

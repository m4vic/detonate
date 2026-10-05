# pr-annotation-demo

A poisoned MCPB manifest used once, on a throwaway pull request, to prove the
claim in `docs/PLAN.md` that findings appear inline on the diff.

The proof has to be a pull request that *adds* a poisoned file: GitHub renders a
code-scanning alert as an annotation only when the alert's line is in the diff.
Scanning a fixture that already exists on `main` uploads an alert that nobody
reviewing a change would ever see.

This directory and the workflow that scans it are not merged. They exist on the
demo branch only, so detonate's own Security tab is not permanently filled with
alerts about detonate's own fixtures.

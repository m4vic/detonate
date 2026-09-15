# The detonate contract

A pipeline that gates on detonate depends on a few things never changing
meaning underneath it. This is the list of what is frozen, and the rule for how
it may change. Everything here is enforced by a test that fails loudly in
review (`internal/cli/contract_test.go`), so a break is a deliberate, reviewed
act rather than a surprise in someone else's CI.

## What is frozen

**Exit codes.** These are what a CI job actually branches on.

| Code | Meaning |
|---:|---|
| `0` | clean — coverage was established and nothing was found |
| `1` | the scan itself broke |
| `2` | usage or environment problem |
| `3` | findings |
| `4` | coverage could not be established (or `--fail-incomplete` and coverage was short) |

`1` and `3` are deliberately distinct: a consumer must be able to tell a
detonate bug from a real finding in the target. `0` means the coverage question
was *answerable* and the answer was "nothing found" — never "the target is
safe."

**Machine-readable schema identifiers.** A consumer keys on these to know which
fields it can rely on:

- `detonate.report/v1` — the JSON report (`--format json`).
- `detonate.bundle/v1` — a saved report bundle, replayed by `detonate report`.

**SARIF property names.** `detonateRisk` and `detonateCompleteness` in the
run's `properties`, plus the frozen `level` mapping (a finding is a `level`
consumers can gate on). SARIF is otherwise shaped by the spec, not by us.

## The rule

**Additive changes are not breaking, and ship in a normal release:**

- new exit *situations* mapped onto the existing codes (never a new number)
- new fields under an existing schema identifier
- new flags, new output sections, reformatted human text

A consumer that matches on the schema identifier and reads the fields it knows
keeps working across all of these.

**Breaking changes require a new identifier and a major release:**

- changing or removing the meaning of an exit code
- changing or removing a schema field, or a SARIF property name
- narrowing what `0` promises

Any of these ships only as `detonate.report/v2` (etc.) **and** a major version
bump, never as a silent edit to `/v1`.

## Deprecation process

1. Announce the change in [CHANGELOG.md](../CHANGELOG.md) one minor release
   before it lands, with the replacement named.
2. Where feasible, emit both the old and the new form for one minor cycle so
   consumers can migrate without a flag day.
3. Remove the old form only at the next **major** version.

## When this takes effect

The contract is a hard guarantee **as of `1.0`**. Before `1.0` (the current
`0.x` line) the exit codes and schema identifiers above are already stable in
practice and treated as frozen, but the `0.x` disclaimer in the README still
holds: other flags and report fields may still move while the tool converges on
`1.0`.

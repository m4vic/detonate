#!/usr/bin/env python3
"""Assert that a SARIF log's findings point at real files and real lines.

An upload to GitHub code scanning succeeds whether or not the locations in it
mean anything. A result whose location is a directory, or a bare basename that
exists nowhere in the checkout, is accepted, counted, and attached to nothing —
so the Security tab shows an alert with no code behind it and the pull request
shows no annotation at all. That is how detonate's SARIF integration stayed
broken across four releases while every upload step reported success.

This checks the thing the upload cannot: that a reviewer looking at the diff
would actually see the finding. Run it on the SARIF, from the directory the
scan ran in.

    python3 scripts/assert-sarif-locations.py detonate.sarif

Observations (SARIF level "note") are exempt. They are context about the run
rather than a claim about a line, and detonate deliberately does not invent a
source location for behaviour it watched at runtime.
"""

import json
import os
import sys


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else "detonate.sarif"

    try:
        with open(path, encoding="utf-8") as fh:
            log = json.load(fh)
    except OSError as err:
        print(f"cannot read {path}: {err}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as err:
        print(f"{path} is not valid JSON: {err}", file=sys.stderr)
        return 2

    runs = log.get("runs") or []
    if not runs:
        print(f"{path} contains no runs", file=sys.stderr)
        return 2

    problems: list[str] = []
    annotated = 0

    for result in runs[0].get("results") or []:
        if result.get("level") not in ("error", "warning"):
            continue

        rule = result.get("ruleId", "(no rule)")
        locations = result.get("locations") or []
        if not locations:
            problems.append(f"{rule}: carries no location at all")
            continue

        physical = locations[0].get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        if not uri:
            problems.append(f"{rule}: location has no uri")
            continue

        if not os.path.isfile(uri):
            what = "a directory" if os.path.isdir(uri) else "not present in the checkout"
            problems.append(
                f"{rule}: points at {uri!r}, which is {what}; "
                "GitHub has nothing in the diff to annotate"
            )
            continue

        line = (physical.get("region") or {}).get("startLine")
        if not line:
            problems.append(f"{rule}: points at {uri} but carries no line")
            continue

        annotated += 1
        print(f"  {rule} -> {uri}:{line}")

    if problems:
        print(f"\n{path}: {len(problems)} finding(s) cannot be annotated:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    if annotated == 0:
        print(
            f"{path}: no finding could be annotated on a file, so nothing "
            "would appear on a pull request",
            file=sys.stderr,
        )
        return 1

    print(f"{annotated} finding(s) resolve to a real file and line")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

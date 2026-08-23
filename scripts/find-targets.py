#!/usr/bin/env python3
"""Find MCP servers detonate can actually probe.

"Where do I get servers to test?" has a bad answer and a good one. The bad
answer is a curated awesome-list: hand-picked, stale, and biased toward the
servers everyone already looks at. The good answer is the official registry,
which states for every server whether it ships as an installable package, how
it speaks, and whether it demands credentials.

Those three facts decide whether detonate can say anything at all:

  * A remote server is an HTTPS endpoint someone else operates. There is no
    code to sandbox, and probing it would be attacking a live third-party
    service. Excluded, and it is most of the registry.
  * A server that requires an API key cannot be exercised offline. The sandbox
    denies egress on purpose, so every tool fails at the network and the scan
    reports `unsupported` — true, and useless.
  * A stdio package from npm or PyPI is the shape detonate was built for.

Usage:
    python scripts/find-targets.py                 # ready-to-probe servers
    python scripts/find-targets.py --all           # include ones needing secrets
    python scripts/find-targets.py --limit 500     # scan more of the registry
    python scripts/find-targets.py --format sh     # emit runnable commands

Nothing here contacts a target. It reads the registry index only.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
PAGE = 100


def fetch(cursor=None):
    url = f"{REGISTRY}?limit={PAGE}"
    if cursor:
        url += f"&cursor={urllib.parse.quote(cursor)}"
    req = urllib.request.Request(url, headers={"User-Agent": "detonate-find-targets"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def crawl(limit):
    seen, cursor = [], None
    while len(seen) < limit:
        try:
            page = fetch(cursor)
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"registry unreachable: {e}", file=sys.stderr)
            break
        servers = page.get("servers", [])
        if not servers:
            break
        seen.extend(servers)
        cursor = page.get("metadata", {}).get("nextCursor")
        if not cursor:
            break
    return seen[:limit]


def classify(entry):
    """Return (package, reason) — reason is None when it is probeable."""
    server = entry.get("server", {})
    packages = server.get("packages") or []

    if not packages:
        return None, "remote only; no code to sandbox"

    for pkg in packages:
        if pkg.get("registryType") not in ("npm", "pypi"):
            continue
        if (pkg.get("transport") or {}).get("type") != "stdio":
            continue

        required = [
            v["name"]
            for v in (pkg.get("environmentVariables") or [])
            if v.get("isRequired")
        ]
        if required:
            return pkg, "needs " + ", ".join(required[:3])
        return pkg, None

    return None, "no stdio npm/pypi package"


def versionKey(v):
    """Sort versions numerically so 0.2.13 beats 0.2.9, which strings do not."""
    if not v:
        return ()
    parts = []
    for chunk in str(v).replace("-", ".").split("."):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, 0))
    return tuple(parts)


def command_for(pkg):
    ident, version = pkg["identifier"], pkg.get("version", "")
    if pkg["registryType"] == "npm":
        spec = f"{ident}@{version}" if version else ident
        return f'npx -y {spec}'
    spec = f"{ident}=={version}" if version else ident
    return f'pip install {spec} && python -m {ident.replace("-", "_")}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=300, help="registry entries to read")
    ap.add_argument("--all", action="store_true", help="include servers needing secrets")
    ap.add_argument("--format", choices=("text", "sh", "json"), default="text")
    args = ap.parse_args()

    entries = crawl(args.limit)
    ready, blocked, remote = [], [], 0

    # The registry lists every published version, so one server can appear a
    # dozen times. Probing the same server nine times measures nothing except
    # how patient you are.
    latest = {}
    for e in entries:
        pkg, reason = classify(e)
        name = e.get("server", {}).get("name", "?")
        if pkg is None:
            remote += 1
            continue
        key = (name, pkg["registryType"])
        prior = latest.get(key)
        if prior is None or versionKey(pkg.get("version")) > versionKey(prior[1].get("version")):
            latest[key] = (name, pkg, reason)

    # Sort by name only. Sorting whole tuples falls through to comparing the
    # package dicts whenever two names tie, which Python refuses to do.
    for name, pkg, reason in sorted(latest.values(), key=lambda t: (t[0], t[1]["registryType"])):
        (blocked if reason else ready).append((name, pkg, reason))

    if args.format == "json":
        print(json.dumps(
            [{"name": n, "package": p, "blocked": r} for n, p, r in ready + blocked],
            indent=2))
        return

    if args.format == "sh":
        print("# Each server runs as untrusted code. detonate sandboxes it; the")
        print("# npx/pip step below does NOT. Install inside a container or a VM.")
        for name, pkg, _ in ready:
            print(f"\n# {name}")
            print(f"# {command_for(pkg)}")
        return

    print(f"read {len(entries)} registry entries\n")
    print(f"  {len(ready):>4}  ready to probe - stdio package, no credentials required")
    print(f"  {len(blocked):>4}  packaged but need secrets")
    print(f"  {remote:>4}  remote only - someone else's live service, not ours to probe\n")

    for name, pkg, _ in ready:
        print(f"  [{pkg['registryType']:>4}] {name}")
        print(f"         {command_for(pkg)}")

    if args.all and blocked:
        print("\n  --- need credentials; scans report `unsupported`, not findings ---")
        for name, pkg, reason in blocked:
            print(f"  [{pkg['registryType']:>4}] {name}  ({reason})")


if __name__ == "__main__":
    import urllib.parse  # noqa: E402  (used by fetch)

    main()

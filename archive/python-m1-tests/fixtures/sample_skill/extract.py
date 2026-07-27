"""Fixture bundled script for testing skill_loader's script discovery. Not a
real PDF extractor — just needs to exist as a file for the loader to find."""

import sys

if __name__ == "__main__":
    print(f"(fixture) would extract: {sys.argv[1] if len(sys.argv) > 1 else '(no path given)'}")

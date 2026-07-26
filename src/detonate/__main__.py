"""Enables `python -m detonate` — a convenient way to run the CLI without
installing the package (useful while developing and while recording).
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())

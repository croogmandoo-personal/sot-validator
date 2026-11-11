"""Module entrypoint for `python3 -m sot_validator`."""

from __future__ import annotations

import sys

from sot_validator.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

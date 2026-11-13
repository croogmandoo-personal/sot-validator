"""Top-level `sot-validator` argparse parser, subcommand registration order, and `main()`."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import Optional

from sot_validator.cli import (
    campaign,
    core,
    discovery,
    history,
    itsm,
    migration,
    ports,
    remediation,
    topology,
    ups,
    workbench,
)

# Registration order is the order subcommands appear in the top-level `--help`.
COMMAND_MODULES = (
    core,
    history,
    remediation,
    campaign,
    ports,
    migration,
    ups,
    itsm,
    discovery,
    workbench,
    topology,
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argparse CLI parser for `sot-validator`."""
    parser = argparse.ArgumentParser(
        prog="sot-validator",
        description="Read-only batch inventory validation system for legacy Network Source of Truth.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    for module in COMMAND_MODULES:
        module.register(subparsers)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entrypoint returning an exit code (0 on success)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args))

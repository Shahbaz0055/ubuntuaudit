"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .checks import CHECKS, FAIL
from .report import render


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ubuntuaudit",
        description="Check an Ubuntu system for common security problems.",
        epilog="Exit status is 1 when any check fails and 0 otherwise.",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        choices=sorted(CHECKS),
        metavar="CHECK",
        help="run only these checks: " + ", ".join(sorted(CHECKS)),
    )
    parser.add_argument(
        "--no-color", action="store_true", help="turn off colored output"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    selected = args.only or list(CHECKS)

    results = []
    for key in selected:
        results.extend(CHECKS[key]())

    color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    print(render(results, color=color))
    return 1 if any(r.status == FAIL for r in results) else 0

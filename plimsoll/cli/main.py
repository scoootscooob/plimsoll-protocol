"""
Plimsoll Protocol CLI — ``plimsoll init | up | status``

Entry point registered as ``plimsoll`` in pyproject.toml ``[project.scripts]``.
Uses only the stdlib (argparse) to keep dependencies at zero.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="plimsoll",
        description="Plimsoll Protocol CLI \u2014 Circuit breaker for autonomous AI agents",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── plimsoll init ─────────────────────────────────────────────────
    subparsers.add_parser(
        "init",
        help="Generate an plimsoll.toml configuration file interactively",
    )

    # ── plimsoll up ───────────────────────────────────────────────────
    up_parser = subparsers.add_parser(
        "up",
        help="Start the Dockerized Plimsoll RPC Proxy",
    )
    up_parser.add_argument(
        "--detach", "-d",
        action="store_true",
        help="Run containers in the background",
    )
    up_parser.add_argument(
        "--compose-file",
        default=None,
        help="Explicit path to docker-compose.yml (auto-detected if omitted)",
    )

    # ── plimsoll status ───────────────────────────────────────────────
    subparsers.add_parser(
        "status",
        help="Check Plimsoll RPC Proxy health",
    )

    args = parser.parse_args(argv)

    if args.command == "init":
        from plimsoll.cli.init_cmd import run_init
        run_init()
    elif args.command == "up":
        from plimsoll.cli.up_cmd import run_up
        run_up(detach=args.detach, compose_file=args.compose_file)
    elif args.command == "status":
        from plimsoll.cli.up_cmd import run_status
        run_status()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

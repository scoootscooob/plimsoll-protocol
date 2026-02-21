"""
``plimsoll up``  — Start the Dockerized Plimsoll RPC Proxy.
``plimsoll status`` — Ping the proxy health endpoint.

Locates ``docker-compose.yml`` automatically (project root → package
directory fallback), optionally loads ``plimsoll.toml`` into the
environment, and delegates to ``docker compose``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import urllib.request
from typing import Optional


# ── Compose-file discovery ────────────────────────────────────────

_COMPOSE_CANDIDATES = [
    # Relative to the current working directory
    os.path.join("plimsoll-rpc", "docker-compose.yml"),
    "docker-compose.yml",
    # Relative to this Python file (package install)
    os.path.join(os.path.dirname(__file__), "..", "..", "plimsoll-rpc", "docker-compose.yml"),
]


def _find_compose_file() -> Optional[str]:
    for candidate in _COMPOSE_CANDIDATES:
        abspath = os.path.abspath(candidate)
        if os.path.isfile(abspath):
            return abspath
    return None


# ── Minimal TOML→env loader (stdlib only) ─────────────────────────

def _load_toml_env(path: str) -> None:
    """Parse a *simple* TOML file and export key=value pairs as env vars.

    This handles flat ``key = "value"`` and ``key = 123`` lines only.
    Section headers (``[section]``) are used as prefixes:
    ``[velocity]`` + ``v_max = 0.01`` → ``PLIMSOLL_VELOCITY_V_MAX=0.01``.
    """
    section = "plimsoll"
    with open(path) as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].strip()
                continue
            if "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            env_key = f"PLIMSOLL_{section.upper()}_{key.upper()}" if section != "plimsoll" else f"PLIMSOLL_{key.upper()}"
            os.environ.setdefault(env_key, value)


# ── Commands ──────────────────────────────────────────────────────

def run_up(
    detach: bool = False,
    compose_file: Optional[str] = None,
) -> None:
    """Start the Plimsoll RPC Proxy via ``docker compose``."""
    cfile = compose_file or _find_compose_file()
    if cfile is None:
        print(
            "Error: docker-compose.yml not found.\n"
            "Run `plimsoll up` from the project root, or pass --compose-file."
        )
        sys.exit(1)

    # Optionally load plimsoll.toml
    toml_path = os.path.join(os.getcwd(), "plimsoll.toml")
    if os.path.isfile(toml_path):
        _load_toml_env(toml_path)
        print(f"  Loaded config from {toml_path}")

    cmd = ["docker", "compose", "-f", cfile, "up", "--build"]
    if detach:
        cmd.append("-d")

    print(f"  Starting Plimsoll RPC Proxy ({cfile}) ...")
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("Error: `docker` not found. Please install Docker.")
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"Error: docker compose exited with code {exc.returncode}")
        sys.exit(exc.returncode)


def run_status(host: str = "localhost", port: int = 8545) -> None:
    """Ping ``/health`` and print the response."""
    url = f"http://{host}:{port}/health"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode()
            print(f"  \u2705  {body}")
    except Exception as exc:
        print(f"  \u274c  Plimsoll RPC Proxy not reachable at {url}: {exc}")
        sys.exit(1)

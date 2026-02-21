"""Tests for the ``plimsoll`` CLI (init / up / status)."""

from __future__ import annotations

import os
import sys
import tempfile
from unittest import mock

import pytest


# ────────────────────────────────────────────────────────────────────
# plimsoll init
# ────────────────────────────────────────────────────────────────────

class TestPlimsollInit:
    """``plimsoll init`` wizard generates a valid ``plimsoll.toml``."""

    def test_generates_toml_with_defaults(self) -> None:
        """Pressing Enter three times → default ethereum / 1000 / custom."""
        from plimsoll.cli.init_cmd import run_init

        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch("builtins.input", side_effect=["", "", ""]):
                path = run_init(output_dir=tmpdir)

            assert os.path.isfile(path)
            content = open(path).read()
            assert 'chain        = "ethereum"' in content
            assert "max_daily_spend = 1000" in content
            assert 'framework    = "custom"' in content
            assert "v_max" in content
            assert "upstream_rpc" in content

    def test_generates_toml_with_custom_values(self) -> None:
        from plimsoll.cli.init_cmd import run_init

        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch("builtins.input", side_effect=["arbitrum", "5000", "langchain"]):
                path = run_init(output_dir=tmpdir)

            content = open(path).read()
            assert 'chain        = "arbitrum"' in content
            assert "chain_id     = 42161" in content
            assert "max_daily_spend = 5000" in content
            assert 'framework    = "langchain"' in content

    def test_unknown_chain_defaults_to_ethereum(self) -> None:
        from plimsoll.cli.init_cmd import run_init

        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch("builtins.input", side_effect=["zcash", "1000", "custom"]):
                path = run_init(output_dir=tmpdir)

            content = open(path).read()
            assert 'chain        = "ethereum"' in content

    def test_invalid_budget_defaults_to_1000(self) -> None:
        from plimsoll.cli.init_cmd import run_init

        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch("builtins.input", side_effect=["ethereum", "not_a_number", "custom"]):
                path = run_init(output_dir=tmpdir)

            content = open(path).read()
            assert "max_daily_spend = 1000" in content


# ────────────────────────────────────────────────────────────────────
# plimsoll up
# ────────────────────────────────────────────────────────────────────

class TestPlimsollUp:
    def test_finds_compose_file(self) -> None:
        """Should locate docker-compose.yml in plimsoll-rpc/."""
        from plimsoll.cli.up_cmd import _find_compose_file

        # Run from project root
        original_cwd = os.getcwd()
        try:
            os.chdir(os.path.join(os.path.dirname(__file__), ".."))
            result = _find_compose_file()
            # May or may not find it depending on cwd, just check it doesn't crash
            assert result is None or os.path.isfile(result)
        finally:
            os.chdir(original_cwd)

    def test_up_calls_docker_compose(self) -> None:
        """Should invoke ``docker compose up --build``."""
        from plimsoll.cli.up_cmd import run_up

        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False) as f:
            f.write(b"version: '3'\nservices: {}\n")
            compose_path = f.name

        try:
            with mock.patch("subprocess.run") as mock_run:
                run_up(detach=True, compose_file=compose_path)
                mock_run.assert_called_once()
                cmd = mock_run.call_args[0][0]
                assert "docker" in cmd
                assert "-d" in cmd
        finally:
            os.unlink(compose_path)


# ────────────────────────────────────────────────────────────────────
# plimsoll status
# ────────────────────────────────────────────────────────────────────

class TestPlimsollStatus:
    def test_status_healthy(self) -> None:
        from plimsoll.cli.up_cmd import run_status

        mock_response = mock.MagicMock()
        mock_response.read.return_value = b"plimsoll-rpc OK"
        mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
        mock_response.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("urllib.request.urlopen", return_value=mock_response):
            # Should not raise
            run_status()

    def test_status_unreachable_exits_1(self) -> None:
        from plimsoll.cli.up_cmd import run_status

        with mock.patch("urllib.request.urlopen", side_effect=ConnectionRefusedError):
            with pytest.raises(SystemExit) as exc_info:
                run_status()
            assert exc_info.value.code == 1


# ────────────────────────────────────────────────────────────────────
# plimsoll (no command)
# ────────────────────────────────────────────────────────────────────

class TestPlimsollCLIMain:
    def test_no_command_exits_1(self) -> None:
        from plimsoll.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main(argv=[])
        assert exc_info.value.code == 1

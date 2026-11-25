"""Offline checks for scripts/fetch_lightwell_packages.py.

No test in this module opens a network connection. Token exchange is stubbed,
and the missing-credentials path asserts urllib is never called.
"""

from __future__ import annotations

import ast
import os
import py_compile
import re
import subprocess
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fetch_lightwell_packages.py"
sys.path.insert(0, str(ROOT / "scripts"))

import fetch_lightwell_packages as fetch  # noqa: E402

CRED_KEYS = (
    "LW_BEARER_TOKEN",
    "LW_OFFLINE_TOKEN",
    "LW_CLIENT_ID",
    "LW_CLIENT_SECRET",
    "CONSOLE_CLIENT_ID",
    "CONSOLE_CLIENT_SECRET",
)


@contextmanager
def credential_env(**values: str):
    """Expose only the credential variables passed in."""
    with patch.dict(os.environ, {}, clear=False):
        for key in CRED_KEYS:
            os.environ.pop(key, None)
        os.environ.update(values)
        yield


def namespace(**flags):
    return SimpleNamespace(
        token=flags.get("token"),
        offline_token=flags.get("offline_token"),
        client_id=flags.get("client_id"),
        client_secret=flags.get("client_secret"),
    )


def top_level_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise AssertionError(f"{path.name} uses a relative import")
            if node.module:
                modules.append(node.module.split(".")[0])
    return modules


class FetchScriptTest(unittest.TestCase):
    def test_byte_compiles(self):
        py_compile.compile(str(SCRIPT), doraise=True)

    def test_imports_stay_in_the_standard_library(self):
        allowed = sys.stdlib_module_names | {"__future__"}
        for path in sorted((ROOT / "scripts").glob("*.py")):
            for name in top_level_imports(path):
                self.assertIn(name, allowed, f"{path.name} imports {name}")

    def test_help_exits_zero_for_every_command(self):
        env = os.environ.copy()
        for key in CRED_KEYS:
            env.pop(key, None)
        # Keep the usage line's {command,command} group on one line.
        env["COLUMNS"] = "240"
        top = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        self.assertEqual(top.returncode, 0, top.stderr)
        match = re.search(r"\{([^}]+)\}", top.stdout)
        self.assertIsNotNone(match, top.stdout)
        commands = match.group(1).split(",")
        self.assertIn("packages", commands)
        for command in commands:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), command, "--help"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            self.assertEqual(result.returncode, 0, f"{command}\n{result.stderr}")

    def test_missing_credentials_exit_before_any_network_call(self):
        env = os.environ.copy()
        for key in CRED_KEYS:
            env.pop(key, None)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "packages"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("missing credentials", result.stderr)

        with patch.dict(os.environ, {}, clear=True):
            with patch.object(sys, "argv", ["fetch_lightwell_packages.py", "packages"]):
                with patch.object(
                    fetch.urllib.request,
                    "urlopen",
                    side_effect=AssertionError("network call"),
                ):
                    with self.assertRaises(SystemExit) as caught:
                        fetch.main()
        self.assertIn("missing credentials", str(caught.exception))

    def resolve(self, env=None, **flags) -> str:
        with credential_env(**(env or {})):
            with patch.object(
                fetch.urllib.request, "urlopen", side_effect=AssertionError("network call")
            ):
                with patch.object(
                    fetch, "get_bearer_token", side_effect=lambda client_id, secret: f"sa:{client_id}:{secret}"
                ):
                    with patch.object(
                        fetch,
                        "get_token_from_offline_token",
                        side_effect=lambda token: f"off:{token}",
                    ):
                        return fetch.resolve_token(namespace(**flags))

    def test_explicit_flag_beats_lower_tier_environment(self):
        everything = {
            "LW_BEARER_TOKEN": "env-bearer",
            "LW_OFFLINE_TOKEN": "env-offline",
            "LW_CLIENT_ID": "env-id",
            "LW_CLIENT_SECRET": "env-secret",
        }
        self.assertEqual(
            self.resolve(
                token="flag-token",
                offline_token="flag-offline",
                client_id="flag-id",
                client_secret="flag-secret",
                env=everything,
            ),
            "flag-token",
        )
        self.assertEqual(
            self.resolve(offline_token="flag-offline", env=everything),
            "off:flag-offline",
        )
        self.assertEqual(
            self.resolve(client_id="flag-id", client_secret="flag-secret", env=everything),
            "sa:flag-id:flag-secret",
        )
        self.assertEqual(
            self.resolve(client_id="flag-id", env=everything),
            "sa:flag-id:env-secret",
        )
        self.assertEqual(
            self.resolve(client_secret="flag-secret", env=everything),
            "sa:env-id:flag-secret",
        )

    def test_environment_order_is_bearer_then_offline_then_service_account(self):
        self.assertEqual(
            self.resolve(
                env={
                    "LW_BEARER_TOKEN": "env-bearer",
                    "LW_OFFLINE_TOKEN": "env-offline",
                    "LW_CLIENT_ID": "env-id",
                    "LW_CLIENT_SECRET": "env-secret",
                }
            ),
            "env-bearer",
        )
        self.assertEqual(
            self.resolve(
                env={
                    "LW_OFFLINE_TOKEN": "env-offline",
                    "LW_CLIENT_ID": "env-id",
                    "LW_CLIENT_SECRET": "env-secret",
                }
            ),
            "off:env-offline",
        )
        self.assertEqual(
            self.resolve(env={"LW_CLIENT_ID": "env-id", "LW_CLIENT_SECRET": "env-secret"}),
            "sa:env-id:env-secret",
        )
        self.assertEqual(
            self.resolve(
                env={"CONSOLE_CLIENT_ID": "console-id", "CONSOLE_CLIENT_SECRET": "console-secret"}
            ),
            "sa:console-id:console-secret",
        )

    def test_partial_client_flag_does_not_fall_through_to_bearer_env(self):
        with credential_env(LW_BEARER_TOKEN="env-bearer"):
            with patch.object(
                fetch, "get_bearer_token", side_effect=AssertionError("token exchange")
            ):
                with self.assertRaises(SystemExit) as caught:
                    fetch.resolve_token(namespace(client_id="flag-id"))
        self.assertIn("missing credentials", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

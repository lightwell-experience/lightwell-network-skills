"""Offline checks for scripts/fetch_lightwell_packages.py.

No test in this module opens a network connection. Token exchange is stubbed,
and the missing-credentials path asserts urllib is never called.
"""

from __future__ import annotations

import ast
import io
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
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
        env["COLUMNS"] = "320"
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

    def test_repository_filter_is_sent_on_packages(self):
        with credential_env(LW_BEARER_TOKEN="tok"):
            with patch.object(fetch, "fetch_all", return_value=[]) as fetch_all:
                with patch.object(
                    sys,
                    "argv",
                    ["fetch_lightwell_packages.py", "packages", "--repository", "lightwell-maven"],
                ):
                    with redirect_stdout(io.StringIO()):
                        fetch.main()
        self.assertEqual(fetch_all.call_args.args[0], "/packages")
        self.assertEqual(fetch_all.call_args.args[2]["repository"], "lightwell-maven")

    def test_added_filters_are_forwarded(self):
        cases = [
            (
                ["packages", "--search", "spring", "--sort-by", "name:desc", "--demo"],
                "/packages",
                {"search": "spring", "sort_by": "name:desc", "demo": "true"},
            ),
            (
                ["package-versions", "--demo"],
                "/package_versions",
                {"demo": "true"},
            ),
            (
                ["advisories", "--advisory-id", "RHSA-2024:1234"],
                "/advisories",
                {"advisory_id": "RHSA-2024:1234"},
            ),
            (
                ["repo-packages", "repo-uuid", "--sort-by", "last_updated:asc"],
                "/repositories/repo-uuid/packages",
                {"sort_by": "last_updated:asc"},
            ),
        ]
        for argv, path, expected in cases:
            with self.subTest(command=argv[0]):
                with credential_env(LW_BEARER_TOKEN="tok"):
                    with patch.object(fetch, "fetch_all", return_value=[]) as fetch_all:
                        with patch.object(sys, "argv", ["fetch_lightwell_packages.py", *argv]):
                            with redirect_stdout(io.StringIO()):
                                fetch.main()
                self.assertEqual(fetch_all.call_args.args[0], path)
                sent = fetch_all.call_args.args[2]
                for key, value in expected.items():
                    self.assertEqual(sent[key], value)

    def test_package_versions_rejects_repository_filter(self):
        env = os.environ.copy()
        for key in CRED_KEYS:
            env.pop(key, None)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "package-versions", "--repository", "lightwell-maven"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("unrecognized arguments: --repository", result.stderr)

    def test_maven_commands_call_java_package_paths(self):
        cases = [
            (
                ["maven-versions", "repo-uuid", "org.example", "artifact"],
                "/repositories/repo-uuid/java_packages/org.example/artifact",
            ),
            (
                ["maven-detail", "repo-uuid", "org.example", "artifact", "1.2.3"],
                "/repositories/repo-uuid/java_packages/org.example/artifact/1.2.3",
            ),
        ]
        for argv, path in cases:
            with self.subTest(command=argv[0]):
                with credential_env(LW_BEARER_TOKEN="tok"):
                    with patch.object(fetch, "api_get", return_value={}) as api_get:
                        with patch.object(sys, "argv", ["fetch_lightwell_packages.py", *argv]):
                            with redirect_stdout(io.StringIO()):
                                fetch.main()
                self.assertEqual(api_get.call_args.args[0], path)

    def test_npm_commands_call_javascript_package_paths(self):
        cases = [
            (
                ["npm-versions", "repo-uuid", "@types", "is-odd"],
                "/repositories/repo-uuid/javascript_packages/%40types/is-odd",
            ),
            (
                ["npm-detail", "repo-uuid", "-", "left-pad", "1.0.0"],
                "/repositories/repo-uuid/javascript_packages/-/left-pad/1.0.0",
            ),
        ]
        for argv, path in cases:
            with self.subTest(command=argv[0]):
                with credential_env(LW_BEARER_TOKEN="tok"):
                    with patch.object(fetch, "api_get", return_value={}) as api_get:
                        with patch.object(sys, "argv", ["fetch_lightwell_packages.py", *argv]):
                            with redirect_stdout(io.StringIO()):
                                fetch.main()
                self.assertEqual(api_get.call_args.args[0], path)

    def test_npm_versions_table_labels_scope(self):
        with redirect_stdout(io.StringIO()) as out:
            fetch.print_npm_versions_table(
                {
                    "scope": "@types",
                    "name": "is-odd",
                    "versions": [
                        {"version": "3.0.0", "last_updated": "2024-01-01", "builds": [{}]}
                    ],
                }
            )
        text = out.getvalue()
        self.assertIn("@types/is-odd", text)
        self.assertIn("3.0.0", text)

        with redirect_stdout(io.StringIO()) as out:
            fetch.print_npm_versions_table(
                {
                    "scope": "-",
                    "name": "left-pad",
                    "versions": [{"version": "1.0.0", "builds": []}],
                }
            )
        text = out.getvalue()
        self.assertIn("left-pad\n", text)
        self.assertNotIn("@-", text)

    def test_terms_command_calls_terms_required(self):
        with credential_env(LW_BEARER_TOKEN="tok"):
            with patch.object(
                fetch, "api_get", return_value={"required": True, "site": "lightwell", "events": ["tou"]}
            ) as api_get:
                with patch.object(sys, "argv", ["fetch_lightwell_packages.py", "terms"]):
                    with redirect_stdout(io.StringIO()) as out:
                        fetch.main()
        self.assertEqual(api_get.call_args.args[0], "/terms/required")
        self.assertIn("Terms acceptance is required.", out.getvalue())
        self.assertIn("tou", out.getvalue())

    def test_terms_table_reports_when_acceptance_is_not_required(self):
        with redirect_stdout(io.StringIO()) as out:
            fetch.print_terms({"required": False})
        self.assertIn("Terms acceptance is not required.", out.getvalue())

    def test_api_get_explains_terms_precondition(self):
        err = fetch.urllib.error.HTTPError(
            url="https://console.redhat.com/api/lightwell/v0.1/packages",
            code=428,
            msg="Precondition Required",
            hdrs=None,
            fp=io.BytesIO(b'{"errors":[{"title":"Terms acceptance required"}]}'),
        )
        with patch.object(fetch.urllib.request, "urlopen", side_effect=err):
            with self.assertRaises(SystemExit) as caught:
                fetch.api_get("/packages", "tok", {})
        message = str(caught.exception)
        self.assertIn("428", message)
        self.assertIn("terms command", message)

    def test_submission_help_exits_zero_for_every_action(self):
        env = os.environ.copy()
        for key in CRED_KEYS:
            env.pop(key, None)
        env["COLUMNS"] = "320"
        top = subprocess.run(
            [sys.executable, str(SCRIPT), "submissions", "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        self.assertEqual(top.returncode, 0, top.stderr)
        match = re.search(r"\{([^}]+)\}", top.stdout)
        self.assertIsNotNone(match, top.stdout)
        for action in match.group(1).split(","):
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "submissions", action, "--help"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            self.assertEqual(result.returncode, 0, f"{action}\n{result.stderr}")

    def test_encode_multipart_repeats_file_fields(self):
        body, content_type = fetch.encode_multipart(
            [("name", "scan")],
            [("file", "vulns.csv", b"vulnerability_id,packageurl\n")],
        )
        self.assertIn("multipart/form-data; boundary=", content_type)
        self.assertIn(b'name="name"', body)
        self.assertIn(b"scan", body)
        self.assertIn(b'filename="vulns.csv"', body)
        self.assertIn(b"vulnerability_id,packageurl", body)

    def test_submissions_list_and_packages_use_collection_endpoints(self):
        cases = [
            (
                ["submissions", "list"],
                "/clearinghouse/submissions",
                {},
            ),
            (
                ["submissions", "packages", "sub-uuid", "--ecosystem", "Java,Unknown", "--valid-purl", "false"],
                "/clearinghouse/submissions/sub-uuid/packages",
                {"ecosystem": "Java,Unknown", "valid_purl": "false"},
            ),
        ]
        for argv, path, expected in cases:
            with self.subTest(command=" ".join(argv)):
                with credential_env(LW_BEARER_TOKEN="tok"):
                    with patch.object(fetch, "fetch_all", return_value=[]) as fetch_all:
                        with patch.object(sys, "argv", ["fetch_lightwell_packages.py", *argv]):
                            with redirect_stdout(io.StringIO()):
                                fetch.main()
                self.assertEqual(fetch_all.call_args.args[0], path)
                sent = fetch_all.call_args.args[2]
                for key, value in expected.items():
                    self.assertEqual(sent[key], value)

    def test_submission_create_posts_the_json_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b'{"name":"scan","vulnerabilities":[]}')
            path = handle.name
        self.addCleanup(os.remove, path)
        with credential_env(LW_BEARER_TOKEN="tok"):
            with patch.object(
                fetch, "api_request", return_value={"uuid": "abc", "name": "scan", "status": "pending"}
            ) as api_request:
                with patch.object(
                    sys, "argv", ["fetch_lightwell_packages.py", "submissions", "create", "--file", path]
                ):
                    with redirect_stdout(io.StringIO()):
                        fetch.main()
        self.assertEqual(api_request.call_args.args[0], "/clearinghouse/submissions/create")
        self.assertEqual(api_request.call_args.kwargs["method"], "POST")
        self.assertEqual(api_request.call_args.kwargs["headers"]["Content-Type"], "application/json")
        self.assertIn(b'"name":"scan"', api_request.call_args.kwargs["data"])

    def test_submission_create_csv_posts_multipart(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as handle:
            handle.write(b"vulnerability_id,packageurl,title,description\n")
            path = handle.name
        self.addCleanup(os.remove, path)
        with credential_env(LW_BEARER_TOKEN="tok"):
            with patch.object(
                fetch, "api_request", return_value={"uuid": "abc", "name": "scan", "status": "pending"}
            ) as api_request:
                with patch.object(
                    sys,
                    "argv",
                    [
                        "fetch_lightwell_packages.py",
                        "submissions",
                        "create-csv",
                        "--name",
                        "scan",
                        "--file",
                        path,
                    ],
                ):
                    with redirect_stdout(io.StringIO()):
                        fetch.main()
        self.assertEqual(api_request.call_args.args[0], "/clearinghouse/submissions/create/csv")
        self.assertTrue(
            api_request.call_args.kwargs["headers"]["Content-Type"].startswith("multipart/form-data;")
        )
        self.assertIn(b'name="name"', api_request.call_args.kwargs["data"])
        self.assertIn(b"scan", api_request.call_args.kwargs["data"])

    def test_submission_mutations_use_the_documented_methods(self):
        cases = [
            (["submissions", "delete", "sub-uuid"], "/clearinghouse/submissions/sub-uuid", "DELETE"),
            (
                ["submissions", "delete-file", "sub-uuid", "notes.txt"],
                "/clearinghouse/submissions/sub-uuid/files/notes.txt",
                "DELETE",
            ),
            (["submissions", "submit", "sub-uuid"], "/clearinghouse/submissions/sub-uuid/submit", "POST"),
            (
                ["submissions", "process", "sub-uuid"],
                "/clearinghouse/submissions/sub-uuid/process",
                "POST",
            ),
        ]
        for argv, path, method in cases:
            with self.subTest(command=" ".join(argv)):
                with credential_env(LW_BEARER_TOKEN="tok"):
                    with patch.object(
                        fetch, "api_request", return_value={"uuid": "sub-uuid", "status": "submitted"}
                    ) as api_request:
                        with patch.object(sys, "argv", ["fetch_lightwell_packages.py", *argv]):
                            with redirect_stdout(io.StringIO()):
                                fetch.main()
                self.assertEqual(api_request.call_args.args[0], path)
                self.assertEqual(api_request.call_args.kwargs["method"], method)

    def test_submission_download_writes_the_response_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "submission.json")
            with credential_env(LW_BEARER_TOKEN="tok"):
                with patch.object(fetch, "api_request", return_value=b'{"name":"scan"}') as api_request:
                    with patch.object(
                        sys,
                        "argv",
                        [
                            "fetch_lightwell_packages.py",
                            "submissions",
                            "download",
                            "sub-uuid",
                            "--output",
                            output,
                        ],
                    ):
                        with redirect_stdout(io.StringIO()):
                            fetch.main()
            self.assertEqual(
                api_request.call_args.args[0], "/clearinghouse/submissions/sub-uuid/submission"
            )
            self.assertFalse(api_request.call_args.kwargs["json_body"])
            with open(output, "rb") as handle:
                self.assertEqual(handle.read(), b'{"name":"scan"}')

    def test_coverage_report_help_exits_zero_for_every_action(self):
        env = os.environ.copy()
        for key in CRED_KEYS:
            env.pop(key, None)
        env["COLUMNS"] = "240"
        top = subprocess.run(
            [sys.executable, str(SCRIPT), "coverage-reports", "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        self.assertEqual(top.returncode, 0, top.stderr)
        match = re.search(r"\{([^}]+)\}", top.stdout)
        self.assertIsNotNone(match, top.stdout)
        self.assertEqual(match.group(1).split(","), ["create", "get", "packages"])
        for action in match.group(1).split(","):
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "coverage-reports", action, "--help"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            self.assertEqual(result.returncode, 0, f"{action}\n{result.stderr}")

    def test_coverage_report_create_posts_to_the_content_sources_api(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
            handle.write(b'{"bomFormat":"CycloneDX"}')
            path = handle.name
        self.addCleanup(os.remove, path)
        with credential_env(LW_BEARER_TOKEN="tok"):
            with patch.object(
                fetch, "api_request", return_value={"uuid": "report-1", "status": "pending"}
            ) as api_request:
                with patch.object(
                    sys,
                    "argv",
                    [
                        "fetch_lightwell_packages.py",
                        "coverage-reports",
                        "create",
                        "--file",
                        path,
                        "--catalog-source",
                        "db",
                    ],
                ):
                    with redirect_stdout(io.StringIO()):
                        fetch.main()
        self.assertEqual(api_request.call_args.args[0], "/coverage_reports/")
        self.assertEqual(api_request.call_args.kwargs["base"], fetch.COVERAGE_API_BASE)
        self.assertEqual(api_request.call_args.kwargs["method"], "POST")
        body = api_request.call_args.kwargs["data"]
        self.assertIn(b'name="catalog_source"', body)
        self.assertIn(b"db", body)
        self.assertIn(b'name="file"', body)

    def test_coverage_report_reads_use_the_content_sources_api(self):
        with credential_env(LW_BEARER_TOKEN="tok"):
            with patch.object(
                fetch, "api_get", return_value={"uuid": "report-1", "status": "completed", "total": 1}
            ) as api_get:
                with patch.object(
                    sys,
                    "argv",
                    ["fetch_lightwell_packages.py", "coverage-reports", "get", "report-1"],
                ):
                    with redirect_stdout(io.StringIO()):
                        fetch.main()
        self.assertEqual(api_get.call_args.args[0], "/coverage_reports/report-1")
        self.assertEqual(api_get.call_args.kwargs["base"], fetch.COVERAGE_API_BASE)

        with credential_env(LW_BEARER_TOKEN="tok"):
            with patch.object(fetch, "fetch_all", return_value=[]) as fetch_all:
                with patch.object(
                    sys,
                    "argv",
                    [
                        "fetch_lightwell_packages.py",
                        "coverage-reports",
                        "packages",
                        "report-1",
                        "--search",
                        "spring",
                        "--ecosystem",
                        "maven",
                        "--match-status",
                        "exact,partial",
                    ],
                ):
                    with redirect_stdout(io.StringIO()):
                        fetch.main()
        self.assertEqual(fetch_all.call_args.args[0], "/coverage_reports/report-1/packages")
        self.assertEqual(fetch_all.call_args.kwargs["base"], fetch.COVERAGE_API_BASE)
        sent = fetch_all.call_args.args[2]
        self.assertEqual(sent["search"], "spring")
        self.assertEqual(sent["ecosystem"], "maven")
        self.assertEqual(sent["match_status"], "exact,partial")


if __name__ == "__main__":
    unittest.main()

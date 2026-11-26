#!/usr/bin/env python3
"""Check the published OpenAPI contracts used by the Network API skill."""

import json
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path

CONTRACTS = Path(__file__).resolve().parents[1] / ".claude/skills/network-api/contracts"
SPECS = {
    "lightwell": "https://console.redhat.com/api/lightwell/v0.1/openapi.json",
    "coverage": "https://console.redhat.com/api/content-sources/v1.0/openapi.json",
}
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def path_shape(path):
    # A placeholder rename alone does not change the URL sent by the client.
    return re.sub(r"\{[^{}]+\}", "{}", path)


def scoped_spec(spec, scope):
    """Keep covered path/method pairs and their path-level settings."""
    methods = {
        path_shape(path): METHODS.intersection(item)
        for path, item in scope.items()
    }
    paths = {}
    for path, item in spec["paths"].items():
        covered = methods.get(path_shape(path), set())
        if covered.intersection(item):
            paths[path] = {
                key: value for key, value in item.items()
                if key not in METHODS or key in covered
            }
    return {**spec, "paths": paths}


def main():
    failed = False
    with tempfile.TemporaryDirectory() as directory:
        for name, url in SPECS.items():
            print(f"Checking {name} OpenAPI compatibility", flush=True)
            baseline = CONTRACTS / f"{name}.json"
            scope = json.loads(baseline.read_text())["paths"]
            try:
                with urllib.request.urlopen(url, timeout=30) as response:
                    current = scoped_spec(json.load(response), scope)
                revision = Path(directory) / f"{name}.json"
                revision.write_text(json.dumps(current))
                result = subprocess.run([
                    "oasdiff", "breaking", "--fail-on", "ERR",
                    "--allow-external-refs=false", str(baseline), str(revision),
                ], check=False)
                failed |= result.returncode != 0
            except (OSError, ValueError, KeyError, TypeError) as error:
                print(f"Could not check {name} OpenAPI: {error}", flush=True)
                failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

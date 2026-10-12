#!/usr/bin/env python3
"""Fetch Lightwell package information from the console.redhat.com Lightwell Network API.

Authenticates with a Red Hat service account (client-credentials grant against Red Hat
SSO), then queries the /packages and /package_versions endpoints.

The service account must belong to a group granting the "Repositories Viewer" role (no
such group exists by default -- an org admin must create one and add the service account),
or the API will return 403 even with a valid token. See SKILL.md for setup.

Credentials are read from the environment by default and can be overridden on the CLI:
    LW_CLIENT_ID / LW_CLIENT_SECRET   (env; CONSOLE_CLIENT_ID / CONSOLE_CLIENT_SECRET also accepted)
    --client-id / --client-secret     (override env)

Stdlib only -- no third-party dependencies.

Examples:
    ./fetch_lightwell_packages.py packages --ecosystem maven --name spring
    ./fetch_lightwell_packages.py packages --security-level remediated --limit 50
    ./fetch_lightwell_packages.py package-versions --name spring-beans --resolves-cve CVE-2022-22965
    ./fetch_lightwell_packages.py packages --name jackson --json
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

SSO_TOKEN_URL = (
    "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
)
API_BASE = "https://console.redhat.com/api/lightwell/v0.1"

# console.redhat.com pages results; grab them in chunks this size when paginating.
PAGE_SIZE = 100


def get_bearer_token(client_id: str, client_secret: str) -> str:
    """Exchange service-account credentials for a bearer token via the SSO token endpoint."""
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
    ).encode()
    req = urllib.request.Request(
        SSO_TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        sys.exit(
            f"ERROR: token request failed ({e.code} {e.reason}).\n"
            f"Check LW_CLIENT_ID / LW_CLIENT_SECRET.\n{detail}"
        )
    except urllib.error.URLError as e:
        sys.exit(f"ERROR: could not reach SSO token endpoint: {e.reason}")

    token = payload.get("access_token")
    if not token:
        sys.exit("ERROR: token endpoint returned no access_token.")
    return token


def _seg(value: str) -> str:
    """URL-encode a single path segment (so a Maven group with dots/slashes is safe)."""
    return urllib.parse.quote(value, safe="")


def api_get(path: str, token: str, params: dict) -> dict:
    """GET a Lightwell Network API endpoint, returning the parsed JSON body."""
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{API_BASE}{path}"
    if query:
        url = f"{url}?{query}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        if e.code == 401:
            hint = "Token invalid or expired."
        elif e.code == 403:
            hint = (
                "Authenticated but not authorized -- confirm the service account belongs "
                "to a group with the 'Repositories Viewer' role (an org admin must create "
                "one and add the account)."
            )
        else:
            hint = ""
        sys.exit(f"ERROR: {path} returned {e.code} {e.reason}. {hint}\n{detail}")
    except urllib.error.URLError as e:
        sys.exit(f"ERROR: could not reach {url}: {e.reason}")


def fetch_all(
    path: str,
    token: str,
    filters: dict,
    limit: int | None,
    data_key: str = "data",
    total_in_meta: bool = True,
) -> list:
    """Fetch results, paginating with limit/offset until exhausted or `limit` is reached.

    If `limit` is None, fetches every page; otherwise stops once `limit` items are collected.

    `data_key` is the response field holding the result list (`data` for the collection
    endpoints, `results` for `/repositories/{uuid}/packages`). `total_in_meta` picks where
    the total count lives: `meta.count` (collections) vs a top-level `total` field.
    """
    collected: list = []
    offset = 0
    while True:
        page_size = PAGE_SIZE
        if limit is not None:
            remaining = limit - len(collected)
            if remaining <= 0:
                break
            page_size = min(PAGE_SIZE, remaining)
        params = {**filters, "limit": page_size, "offset": offset}
        body = api_get(path, token, params)
        data = body.get(data_key, []) or []
        collected.extend(data)
        if total_in_meta:
            total = (body.get("meta") or {}).get("count")
        else:
            total = body.get("total")
        offset += len(data)
        if not data or (total is not None and offset >= total):
            break
    return collected


def print_packages_table(rows: list) -> None:
    if not rows:
        print("No packages found.")
        return
    header = ["ECOSYSTEM", "NAME", "REPOSITORY", "VERSIONS"]
    lines = ["\t".join(header)]
    for r in rows:
        versions = r.get("versions") or []
        vsummary = f"{len(versions)} version(s)"
        lines.append(
            "\t".join(
                [
                    str(r.get("ecosystem", "")),
                    str(r.get("name", "")),
                    str(r.get("repository", "")),
                    vsummary,
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(rows)} package(s).")


def print_versions_table(rows: list) -> None:
    if not rows:
        print("No package versions found.")
        return
    header = ["ECOSYSTEM", "NAME", "VERSION", "RELEASE", "REPOSITORY"]
    lines = ["\t".join(header)]
    for r in rows:
        lines.append(
            "\t".join(
                [
                    str(r.get("ecosystem", "")),
                    str(r.get("name", "")),
                    str(r.get("version", "")),
                    str(r.get("release", "")),
                    str(r.get("repository", "")),
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(rows)} version(s).")


def print_advisories_table(rows: list) -> None:
    if not rows:
        print("No advisories found.")
        return
    header = ["ADVISORY", "SEVERITY", "PACKAGE", "VERSION", "SUMMARY"]
    lines = ["\t".join(header)]
    for r in rows:
        lines.append(
            "\t".join(
                [
                    str(r.get("advisory_name") or r.get("advisory_id", "")),
                    str(r.get("severity", "")),
                    str(r.get("package_name", "")),
                    str(r.get("package_version", "")),
                    str(r.get("summary", "")),
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(rows)} advisory(ies).")


def print_repositories_table(rows: list) -> None:
    if not rows:
        print("No repositories found.")
        return
    header = ["UUID", "NAME", "CONTENT_TYPE", "SECURITY_LEVEL", "PACKAGES", "URL"]
    lines = ["\t".join(header)]
    for r in rows:
        lines.append(
            "\t".join(
                [
                    str(r.get("uuid", "")),
                    str(r.get("name", "")),
                    str(r.get("content_type", "")),
                    str(r.get("security_level", "")),
                    str(r.get("package_count", "")),
                    str(r.get("url", "")),
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(rows)} repository(ies).")


def print_repo_packages_table(rows: list) -> None:
    if not rows:
        print("No packages found.")
        return
    header = ["GROUP", "NAME", "VERSIONS"]
    lines = ["\t".join(header)]
    for r in rows:
        versions = r.get("versions") or []
        lines.append(
            "\t".join(
                [
                    str(r.get("group", "")),
                    str(r.get("name", "")),
                    f"{len(versions)} version(s)",
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(rows)} package(s).")


def print_maven_versions_table(body: dict) -> None:
    versions = body.get("versions") or []
    if not versions:
        print("No versions found.")
        return
    print(f"{body.get('group', '')}:{body.get('name', '')}")
    header = ["VERSION", "LICENSE", "BUILDS"]
    lines = ["\t".join(header)]
    for v in versions:
        builds = v.get("builds") or []
        lines.append(
            "\t".join(
                [
                    str(v.get("version", "")),
                    str(v.get("license", "")),
                    f"{len(builds)} build(s)",
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(versions)} version(s).")


def print_python_versions_table(body: dict) -> None:
    versions = body.get("versions") or []
    if not versions:
        print("No versions found.")
        return
    print(str(body.get("name", "")))
    header = ["VERSION", "LICENSE", "LAST_UPDATED", "DISTRIBUTIONS"]
    lines = ["\t".join(header)]
    for v in versions:
        dists = v.get("distributions") or []
        lines.append(
            "\t".join(
                [
                    str(v.get("version", "")),
                    str(v.get("license", "")),
                    str(v.get("last_updated", "")),
                    f"{len(dists)} distribution(s)",
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(versions)} version(s).")


def print_detail(body: dict) -> None:
    """Print a single detail object as aligned key/value lines."""
    for key, value in body.items():
        if isinstance(value, (list, dict)):
            value = json.dumps(value)
        print(f"{key}: {value}")


def resolve_credentials(args) -> tuple:
    # LW_* is preferred; CONSOLE_* is kept as a fallback for existing setups.
    client_id = (
        args.client_id
        or os.environ.get("LW_CLIENT_ID")
        or os.environ.get("CONSOLE_CLIENT_ID")
    )
    client_secret = (
        args.client_secret
        or os.environ.get("LW_CLIENT_SECRET")
        or os.environ.get("CONSOLE_CLIENT_SECRET")
    )
    if not client_id or not client_secret:
        sys.exit(
            "ERROR: missing credentials. Set LW_CLIENT_ID and "
            "LW_CLIENT_SECRET (or pass --client-id / --client-secret)."
        )
    return client_id, client_secret


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])

    # Options common to every subcommand. Put on a shared parent parser so they can be
    # given *after* the subcommand (e.g. `packages --name jackson --json`), which is the
    # ordering the docs and examples assume.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--client-id", help="Service-account client ID (overrides env).")
    common.add_argument(
        "--client-secret", help="Service-account client secret (overrides env)."
    )
    common.add_argument("--json", action="store_true", help="Emit raw JSON instead of a table.")
    common.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max results to return (default: all, paginated).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_pkg = sub.add_parser("packages", parents=[common], help="List Lightwell packages (cross-repo).")
    p_pkg.add_argument("--ecosystem", help="Filter by ecosystem: maven, python, npm.")
    p_pkg.add_argument("--name", help="Filter by package name (substring match).")
    p_pkg.add_argument(
        "--security-level",
        help="Filter by security level: validated, remediated, predisclosure.",
    )

    p_ver = sub.add_parser("package-versions", parents=[common], help="List Lightwell package versions.")
    p_ver.add_argument("--ecosystem", help="Filter by ecosystem: maven, python, npm.")
    p_ver.add_argument("--name", help="Filter by package name (substring match).")
    p_ver.add_argument(
        "--security-level",
        help="Filter by security level: validated, remediated, predisclosure.",
    )
    p_ver.add_argument("--repository", help="Filter by repository.")
    p_ver.add_argument(
        "--resolves-cve", dest="resolves_cve", help="Only versions that resolve this CVE ID."
    )
    p_ver.add_argument(
        "--vulnerable-to-cve",
        dest="vulnerable_to_cve",
        help="Only versions vulnerable to this CVE ID.",
    )

    p_adv = sub.add_parser("advisories", parents=[common], help="List Lightwell security advisories.")
    p_adv.add_argument("--repository", help="Filter by repository name.")
    p_adv.add_argument("--package-name", dest="package_name", help="Package name (exact).")
    p_adv.add_argument(
        "--package-version", dest="package_version", help="Package version (exact)."
    )
    p_adv.add_argument("--name", help="Advisory id or alias (substring match).")
    p_adv.add_argument(
        "--severity-min",
        dest="severity_min",
        help="Minimum severity: low, moderate, important, critical.",
    )
    p_adv.add_argument("--cve-id", dest="cve_id", help="Filter by CVE ID (exact).")
    p_adv.add_argument(
        "--latest-release",
        dest="latest_release",
        action="store_true",
        help="Only advisories from the highest rebuild (needs --package-name/--package-version).",
    )

    p_repo = sub.add_parser("repositories", parents=[common], help="List Lightwell repositories.")
    p_repo.add_argument("--search", help="Search term to filter by name or URL.")
    p_repo.add_argument("--name", help="Filter by repository name.")
    p_repo.add_argument(
        "--content-type", dest="content_type", help="Content type: maven, python, npm."
    )
    p_repo.add_argument("--sort-by", dest="sort_by", help="Sort (e.g. name, url, status).")

    p_rpkg = sub.add_parser(
        "repo-packages", parents=[common], help="List packages in a specific repository."
    )
    p_rpkg.add_argument("uuid", help="Repository UUID.")
    p_rpkg.add_argument("--search", help="Search term to filter packages.")

    p_mvers = sub.add_parser(
        "maven-versions", parents=[common], help="List versions of a Maven package in a repository."
    )
    p_mvers.add_argument("uuid", help="Repository UUID.")
    p_mvers.add_argument("group", help="Maven group ID.")
    p_mvers.add_argument("name", help="Maven artifact ID.")

    p_mdet = sub.add_parser(
        "maven-detail", parents=[common], help="Get a specific Maven package version's builds."
    )
    p_mdet.add_argument("uuid", help="Repository UUID.")
    p_mdet.add_argument("group", help="Maven group ID.")
    p_mdet.add_argument("name", help="Maven artifact ID.")
    p_mdet.add_argument("version", help="Maven package version.")

    p_pvers = sub.add_parser(
        "python-versions", parents=[common], help="List versions of a Python package in a repository."
    )
    p_pvers.add_argument("uuid", help="Repository UUID.")
    p_pvers.add_argument("name", help="Python package normalized name.")

    p_pdet = sub.add_parser(
        "python-detail", parents=[common], help="Get a specific Python package version's metadata."
    )
    p_pdet.add_argument("uuid", help="Repository UUID.")
    p_pdet.add_argument("name", help="Python package normalized name.")
    p_pdet.add_argument("version", help="Python package version.")

    args = parser.parse_args()
    client_id, client_secret = resolve_credentials(args)
    token = get_bearer_token(client_id, client_secret)

    if args.command == "packages":
        filters = {
            "ecosystem": args.ecosystem,
            "name": args.name,
            "security_level": args.security_level,
        }
        rows = fetch_all("/packages", token, filters, args.limit)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_packages_table(rows)
    elif args.command == "package-versions":
        filters = {
            "ecosystem": args.ecosystem,
            "name": args.name,
            "security_level": args.security_level,
            "repository": args.repository,
            "resolves_cve": args.resolves_cve,
            "vulnerable_to_cve": args.vulnerable_to_cve,
        }
        rows = fetch_all("/package_versions", token, filters, args.limit)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_versions_table(rows)
    elif args.command == "advisories":
        filters = {
            "repository": args.repository,
            "package_name": args.package_name,
            "package_version": args.package_version,
            "name": args.name,
            "severity_min": args.severity_min,
            "cve_id": args.cve_id,
            "latest_release": "true" if args.latest_release else None,
        }
        rows = fetch_all("/advisories", token, filters, args.limit)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_advisories_table(rows)
    elif args.command == "repositories":
        filters = {
            "search": args.search,
            "name": args.name,
            "content_type": args.content_type,
            "sort_by": args.sort_by,
        }
        rows = fetch_all("/repositories", token, filters, args.limit)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_repositories_table(rows)
    elif args.command == "repo-packages":
        uuid = _seg(args.uuid)
        rows = fetch_all(
            f"/repositories/{uuid}/packages",
            token,
            {"search": args.search},
            args.limit,
            data_key="results",
            total_in_meta=False,
        )
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_repo_packages_table(rows)
    elif args.command == "maven-versions":
        path = f"/repositories/{_seg(args.uuid)}/maven_packages/{_seg(args.group)}/{_seg(args.name)}"
        body = api_get(path, token, {})
        if args.json:
            print(json.dumps(body, indent=2))
        else:
            print_maven_versions_table(body)
    elif args.command == "maven-detail":
        path = (
            f"/repositories/{_seg(args.uuid)}/maven_packages/"
            f"{_seg(args.group)}/{_seg(args.name)}/{_seg(args.version)}"
        )
        body = api_get(path, token, {})
        if args.json:
            print(json.dumps(body, indent=2))
        else:
            print_detail(body)
    elif args.command == "python-versions":
        path = f"/repositories/{_seg(args.uuid)}/python_packages/{_seg(args.name)}"
        body = api_get(path, token, {})
        if args.json:
            print(json.dumps(body, indent=2))
        else:
            print_python_versions_table(body)
    elif args.command == "python-detail":
        path = (
            f"/repositories/{_seg(args.uuid)}/python_packages/"
            f"{_seg(args.name)}/{_seg(args.version)}"
        )
        body = api_get(path, token, {})
        if args.json:
            print(json.dumps(body, indent=2))
        else:
            print_detail(body)


if __name__ == "__main__":
    main()

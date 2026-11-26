#!/usr/bin/env python3
"""Fetch Lightwell package information from the console.redhat.com Lightwell Network API.

Authenticates against Red Hat SSO -- with a service account (client-credentials grant) or
with your own user account (offline token, or a bearer token you already hold) -- then
queries the /packages and /package_versions endpoints.

Whichever identity you use must belong to a group granting the "Repositories Viewer" role
(no such group exists by default -- an org admin must create one and add the account), or
the API will return 403 even with a valid token. See SKILL.md for setup.

Credentials are read from the environment by default. An explicit flag beats an
environment variable from a lower tier, so --offline-token wins over a leftover
LW_BEARER_TOKEN, and --client-id / --client-secret win over both token env vars.
Within flags, then within the environment, the first match wins:
    --token          / LW_BEARER_TOKEN       an access token, used as-is
    --offline-token  / LW_OFFLINE_TOKEN      personal offline token, exchanged for an
                                             access token
                                             (https://access.redhat.com/management/api)
    --client-id      / LW_CLIENT_ID          service account (CONSOLE_CLIENT_ID /
    --client-secret  / LW_CLIENT_SECRET      CONSOLE_CLIENT_SECRET also accepted)

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
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

SSO_TOKEN_URL = (
    "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
)
API_BASE = "https://console.redhat.com/api/lightwell/v0.1"
# Coverage reports are still served by the content-sources API. Point this at
# API_BASE when those routes move onto the Lightwell path.
COVERAGE_API_BASE = "https://console.redhat.com/api/content-sources/v1.0"

# Public SSO client used for the personal offline-token (refresh_token) grant.
OFFLINE_TOKEN_CLIENT_ID = "rhsm-api"

# console.redhat.com pages results; grab them in chunks this size when paginating.
PAGE_SIZE = 100

# Clearinghouse uploads are rejected above these limits.
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_UPLOAD_FILES = 20
# Coverage report manifests are rejected above this limit.
MAX_COVERAGE_UPLOAD_BYTES = 15 * 1024 * 1024


def _sso_token_request(form: dict, hint: str) -> str:
    """POST a grant to the SSO token endpoint and return the access_token."""
    req = urllib.request.Request(
        SSO_TOKEN_URL,
        data=urllib.parse.urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        sys.exit(f"ERROR: token request failed ({e.code} {e.reason}).\n{hint}\n{detail}")
    except urllib.error.URLError as e:
        sys.exit(f"ERROR: could not reach SSO token endpoint: {e.reason}")

    token = payload.get("access_token")
    if not token:
        sys.exit("ERROR: token endpoint returned no access_token.")
    return token


def get_bearer_token(client_id: str, client_secret: str) -> str:
    """Exchange service-account credentials for a bearer token via the SSO token endpoint."""
    return _sso_token_request(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        "Check LW_CLIENT_ID / LW_CLIENT_SECRET.",
    )


def get_token_from_offline_token(offline_token: str) -> str:
    """Exchange a personal offline token for a user-scoped bearer token.

    Offline tokens are issued at https://access.redhat.com/management/api and are
    long-lived refresh tokens for the redhat-external realm; the resulting access token
    carries your own user identity rather than a service account's.
    """
    return _sso_token_request(
        {
            "grant_type": "refresh_token",
            "client_id": OFFLINE_TOKEN_CLIENT_ID,
            "refresh_token": offline_token,
        },
        "Check LW_OFFLINE_TOKEN -- offline tokens expire after 30 days of non-use; "
        "regenerate at https://access.redhat.com/management/api.",
    )


def _seg(value: str) -> str:
    """URL-encode a single path segment (so a Maven group with dots/slashes is safe)."""
    return urllib.parse.quote(value, safe="")


def _http_error_hint(code: int) -> str:
    if code == 401:
        return (
            "Token invalid or expired. A token passed via --token / LW_BEARER_TOKEN "
            "is used as-is and is typically short-lived; use --offline-token or "
            "service-account credentials to have a fresh one fetched each run."
        )
    if code == 403:
        return (
            "Authenticated but not authorized. Package and repository calls need a group "
            "with the 'Repositories Viewer' role. Clearinghouse calls need the Lightwell "
            "clearinghouse feature, or clearinghouse read for process and downloads. "
            "Coverage reports need the Lightwell Lens feature."
        )
    if code == 428:
        return (
            "Lightwell terms have not been accepted. Run the terms command to see "
            "what is required, then accept them at https://console.redhat.com/lightwell."
        )
    return ""


def api_request(
    path: str,
    token: str,
    params: dict | None = None,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict | None = None,
    json_body: bool = True,
    base: str | None = None,
):
    """Call a Lightwell Network API endpoint.

    JSON responses are parsed. An empty success body (such as HTTP 204) returns {}.
    Set `json_body` false to return the raw bytes, for downloads. `base` overrides
    API_BASE for calls that still live on another host.
    """
    query = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{base or API_BASE}{path}"
    if query:
        url = f"{url}?{query}"
    req_headers = {"Authorization": f"Bearer {token}"}
    if headers:
        req_headers.update(headers)
    if method == "POST" and data is None:
        data = b""
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        hint = _http_error_hint(e.code)
        sys.exit(f"ERROR: {path} returned {e.code} {e.reason}. {hint}\n{detail}")
    except urllib.error.URLError as e:
        sys.exit(f"ERROR: could not reach {url}: {e.reason}")
    if not json_body:
        return raw
    if not raw:
        return {}
    return json.loads(raw)


def api_get(path: str, token: str, params: dict, *, base: str | None = None) -> dict:
    """GET a Lightwell Network API endpoint, returning the parsed JSON body."""
    return api_request(path, token, params, base=base)


def encode_multipart(
    fields: list[tuple[str, str]], files: list[tuple[str, str, bytes]]
) -> tuple[bytes, str]:
    """Encode a multipart/form-data body. `files` are (field, filename, content)."""
    boundary = "----lightwell" + secrets.token_hex(16)
    chunks: list[bytes] = []
    for name, value in fields:
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode()
        )
    for field, filename, content in files:
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + content
            + b"\r\n"
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _read_upload(path: str, max_bytes: int = MAX_UPLOAD_BYTES) -> tuple[str, bytes]:
    """Read an upload and return (basename, bytes). Rejects names the form encoder cannot quote."""
    filename = os.path.basename(path)
    if not filename or any(char in filename for char in '"\r\n'):
        sys.exit(f"ERROR: cannot use {path} as an upload filename.")
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as e:
        sys.exit(f"ERROR: could not read {path}: {e}")
    if len(data) > max_bytes:
        sys.exit(f"ERROR: {path} exceeds the {max_bytes} byte upload limit.")
    return filename, data


def _write_output(path: str, data: bytes) -> None:
    try:
        with open(path, "wb") as handle:
            handle.write(data)
    except OSError as e:
        sys.exit(f"ERROR: could not write {path}: {e}")
    print(f"Wrote {len(data)} byte(s) to {path}.")


def _submission_path(uuid: str, *parts: str) -> str:
    path = f"/clearinghouse/submissions/{_seg(uuid)}"
    for part in parts:
        path += "/" + _seg(part)
    return path


def fetch_all(
    path: str,
    token: str,
    filters: dict,
    limit: int | None,
    data_key: str = "data",
    total_in_meta: bool = True,
    *,
    base: str | None = None,
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
        body = api_get(path, token, params, base=base)
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


def display_name(r: dict) -> str:
    """Package name for display; npm packages with a group/scope print as `@group/name`."""
    name = str(r.get("name", "") or "")
    group = r.get("group")
    if str(r.get("ecosystem", "")).lower() == "npm" and group:
        group = str(group)
        if not group.startswith("@"):
            group = f"@{group}"
        if not name.startswith(f"{group}/"):
            name = f"{group}/{name}"
    return name


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
                    display_name(r),
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
                    display_name(r),
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


def print_npm_versions_table(body: dict) -> None:
    versions = body.get("versions") or []
    if not versions:
        print("No versions found.")
        return
    scope = str(body.get("scope") or "")
    name = str(body.get("name") or "")
    if scope and scope != "-":
        if not scope.startswith("@"):
            scope = f"@{scope}"
        print(f"{scope}/{name}")
    else:
        print(name)
    header = ["VERSION", "LAST_UPDATED", "BUILDS"]
    lines = ["\t".join(header)]
    for v in versions:
        builds = v.get("builds") or []
        lines.append(
            "\t".join(
                [
                    str(v.get("version", "")),
                    str(v.get("last_updated", "")),
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


def print_terms(body: dict) -> None:
    """Print the terms-required check."""
    if body.get("required"):
        print("Terms acceptance is required.")
    else:
        print("Terms acceptance is not required.")
    site = body.get("site") or ""
    if site:
        print(f"Site: {site}")
    events = body.get("events") or []
    if events:
        print("Events: " + ", ".join(str(event) for event in events))


def print_submissions_table(rows: list) -> None:
    if not rows:
        print("No submissions found.")
        return
    header = ["UUID", "NAME", "STATUS", "VULNS", "USER", "CREATED"]
    lines = ["\t".join(header)]
    for row in rows:
        lines.append(
            "\t".join(
                [
                    str(row.get("uuid", "")),
                    str(row.get("name", "")),
                    str(row.get("status", "")),
                    str(row.get("vulnerability_count", "")),
                    str(row.get("username", "")),
                    str(row.get("created_at", "")),
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(rows)} submission(s).")


def print_submission(body: dict) -> None:
    """Print one clearinghouse submission, then its files."""
    fields = [
        "uuid",
        "name",
        "status",
        "username",
        "org_id",
        "cid",
        "vulnerability_count",
        "created_at",
        "submitted_at",
        "submitted_by",
        "processed_at",
        "processed_by",
        "error_message",
        "can_submit",
        "can_delete",
        "can_add_reproducers",
        "can_process",
        "can_download",
    ]
    for key in fields:
        value = body.get(key)
        if value not in (None, ""):
            print(f"{key}: {value}")
    summary = body.get("package_summary") or {}
    if summary:
        print(
            f"packages: {summary.get('total', '')} ({summary.get('invalid_purls', 0)} invalid)"
        )
        for ecosystem in summary.get("ecosystems") or []:
            print(f"  {ecosystem.get('ecosystem', '')}: {ecosystem.get('total', '')}")
    files = body.get("files") or []
    if files:
        print("files:")
        for item in files:
            marker = " submission" if item.get("submission") else ""
            print(f"  {item.get('filename', '')}{marker}")


def print_submission_packages_table(rows: list) -> None:
    if not rows:
        print("No packages found.")
        return
    header = ["ECOSYSTEM", "NAME", "VERSION", "VALID", "REASON", "PACKAGEURL"]
    lines = ["\t".join(header)]
    for row in rows:
        lines.append(
            "\t".join(
                [
                    str(row.get("ecosystem", "")),
                    str(row.get("name", "")),
                    str(row.get("version", "")),
                    str(row.get("valid_purl", "")),
                    str(row.get("invalid_reason") or ""),
                    str(row.get("packageurl", "")),
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(rows)} package(s).")


def _cve_counts(counts: dict | None) -> str:
    """Format CVE counts as critical/important/moderate/low."""
    counts = counts or {}
    return "/".join(
        str(counts.get(key, 0)) for key in ("critical", "important", "moderate", "low")
    )


def print_coverage_report(body: dict) -> None:
    fields = [
        "uuid",
        "status",
        "input_format",
        "created_at",
        "completed_at",
        "total",
        "exact_matches",
        "partial_matches",
        "unmatched",
        "skipped_entries",
        "analysis_task_uuid",
        "analysis_task_error",
    ]
    for key in fields:
        value = body.get(key)
        if value not in (None, ""):
            print(f"{key}: {value}")
    if body.get("cve_summary"):
        print(f"cve_summary: {_cve_counts(body.get('cve_summary'))} (critical/important/moderate/low)")
    ecosystems = body.get("ecosystem_coverage_summary") or []
    if ecosystems:
        print("ecosystems:")
        for item in ecosystems:
            supported = "supported" if item.get("supported") else "unsupported"
            print(
                f"  {item.get('ecosystem', '')}: total={item.get('total', '')} "
                f"exact={item.get('exact_matches', '')} "
                f"partial={item.get('partial_matches', '')} "
                f"unmatched={item.get('unmatched', '')} {supported}"
            )


def print_coverage_packages_table(rows: list) -> None:
    if not rows:
        print("No packages found.")
        return
    header = ["ECOSYSTEM", "NAME", "VERSION", "MATCH", "COVERED", "CVES"]
    lines = ["\t".join(header)]
    for row in rows:
        lines.append(
            "\t".join(
                [
                    str(row.get("ecosystem", "")),
                    str(row.get("name", "")),
                    str(row.get("version", "")),
                    str(row.get("match_status", "")),
                    str(row.get("covered", "")),
                    _cve_counts(row.get("cve_count")),
                ]
            )
        )
    print("\n".join(lines))
    print(f"\n{len(rows)} package(s).")
    print("CVES is critical/important/moderate/low.")


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
            "ERROR: missing credentials. Use one of:\n"
            "  LW_BEARER_TOKEN  (or --token)          an access token you already have\n"
            "  LW_OFFLINE_TOKEN (or --offline-token)  your personal offline token\n"
            "  LW_CLIENT_ID + LW_CLIENT_SECRET        a service account\n"
            "(or --client-id / --client-secret)."
        )
    return client_id, client_secret


def resolve_token(args) -> str:
    """Return a bearer token.

    Explicit flags are checked before any environment variable, and within each
    source the order is bearer token, offline token, then service-account
    credentials. A flag therefore beats an environment variable from a lower
    tier: --offline-token wins over LW_BEARER_TOKEN, and --client-id or
    --client-secret wins over both token env vars.
    """
    if args.token:
        return args.token
    if args.offline_token:
        return get_token_from_offline_token(args.offline_token)
    if args.client_id or args.client_secret:
        return get_bearer_token(*resolve_credentials(args))

    token = os.environ.get("LW_BEARER_TOKEN")
    if token:
        return token
    offline_token = os.environ.get("LW_OFFLINE_TOKEN")
    if offline_token:
        return get_token_from_offline_token(offline_token)

    return get_bearer_token(*resolve_credentials(args))


def _show_submission(body: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(body, indent=2))
    else:
        print_submission(body)


def handle_submissions(args, token: str) -> None:
    """Run one clearinghouse submissions action."""
    action = args.submission_action
    if action == "list":
        rows = fetch_all("/clearinghouse/submissions", token, {}, args.limit)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_submissions_table(rows)
        return
    if action == "get":
        body = api_get(_submission_path(args.uuid), token, {})
        _show_submission(body, args.json)
        return
    if action == "create":
        _filename, data = _read_upload(args.file)
        body = api_request(
            "/clearinghouse/submissions/create",
            token,
            method="POST",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        _show_submission(body, args.json)
        return
    if action == "create-csv":
        filename, data = _read_upload(args.file)
        payload, content_type = encode_multipart([("name", args.name)], [("file", filename, data)])
        body = api_request(
            "/clearinghouse/submissions/create/csv",
            token,
            method="POST",
            data=payload,
            headers={"Content-Type": content_type},
        )
        _show_submission(body, args.json)
        return
    if action == "delete":
        api_request(_submission_path(args.uuid), token, method="DELETE")
        print(f"Deleted submission {args.uuid}.")
        return
    if action == "add-files":
        if len(args.files) > MAX_UPLOAD_FILES:
            sys.exit(f"ERROR: at most {MAX_UPLOAD_FILES} files can be uploaded at once.")
        files = []
        for path in args.files:
            filename, data = _read_upload(path)
            files.append(("files", filename, data))
        payload, content_type = encode_multipart([], files)
        body = api_request(
            _submission_path(args.uuid, "files"),
            token,
            method="POST",
            data=payload,
            headers={"Content-Type": content_type},
        )
        _show_submission(body, args.json)
        return
    if action == "delete-file":
        api_request(_submission_path(args.uuid, "files", args.filename), token, method="DELETE")
        print(f"Deleted {args.filename} from submission {args.uuid}.")
        return
    if action == "download":
        data = api_request(_submission_path(args.uuid, "submission"), token, json_body=False)
        _write_output(args.output, data)
        return
    if action == "download-file":
        data = api_request(
            _submission_path(args.uuid, "files", args.filename), token, json_body=False
        )
        _write_output(args.output, data)
        return
    if action == "archive":
        data = api_request(_submission_path(args.uuid, "archive"), token, json_body=False)
        _write_output(args.output, data)
        return
    if action == "packages":
        rows = fetch_all(
            _submission_path(args.uuid, "packages"),
            token,
            {"ecosystem": args.ecosystem, "valid_purl": args.valid_purl},
            args.limit,
        )
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_submission_packages_table(rows)
        return
    if action == "submit":
        body = api_request(_submission_path(args.uuid, "submit"), token, method="POST")
        _show_submission(body, args.json)
        return
    if action == "process":
        body = api_request(_submission_path(args.uuid, "process"), token, method="POST")
        _show_submission(body, args.json)
        return
    sys.exit(f"ERROR: unknown submissions action {action}.")


def _show_coverage_report(body: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(body, indent=2))
    else:
        print_coverage_report(body)


def handle_coverage_reports(args, token: str) -> None:
    """Run one coverage-reports action.

    These routes still use COVERAGE_API_BASE. The paths stay the same when the
    service moves them onto the Lightwell API.
    """
    action = args.coverage_action
    if action == "create":
        filename, data = _read_upload(args.file, MAX_COVERAGE_UPLOAD_BYTES)
        fields = []
        if args.catalog_source:
            fields.append(("catalog_source", args.catalog_source))
        payload, content_type = encode_multipart(fields, [("file", filename, data)])
        body = api_request(
            "/coverage_reports/",
            token,
            method="POST",
            data=payload,
            headers={"Content-Type": content_type},
            base=COVERAGE_API_BASE,
        )
        _show_coverage_report(body, args.json)
        return
    if action == "get":
        body = api_get(
            f"/coverage_reports/{_seg(args.uuid)}",
            token,
            {},
            base=COVERAGE_API_BASE,
        )
        _show_coverage_report(body, args.json)
        return
    if action == "packages":
        rows = fetch_all(
            f"/coverage_reports/{_seg(args.uuid)}/packages",
            token,
            {
                "search": args.search,
                "ecosystem": args.ecosystem,
                "match_status": args.match_status,
            },
            args.limit,
            base=COVERAGE_API_BASE,
        )
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_coverage_packages_table(rows)
        return
    sys.exit(f"ERROR: unknown coverage-reports action {action}.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])

    # Options common to every subcommand. Put on a shared parent parser so they can be
    # given *after* the subcommand (e.g. `packages --name jackson --json`), which is the
    # ordering the docs and examples assume.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--token",
        help="Bearer token to use as-is, e.g. your own user token (overrides every "
        "other credential, including env LW_BEARER_TOKEN).",
    )
    common.add_argument(
        "--offline-token",
        dest="offline_token",
        help="Personal offline token from https://access.redhat.com/management/api, "
        "exchanged for a user-scoped bearer token. Beats env LW_OFFLINE_TOKEN, "
        "LW_BEARER_TOKEN, and service-account environment variables.",
    )
    common.add_argument(
        "--client-id",
        help="Service-account client ID (overrides env LW_CLIENT_ID). An explicit "
        "--client-id or --client-secret beats LW_BEARER_TOKEN and LW_OFFLINE_TOKEN.",
    )
    common.add_argument(
        "--client-secret",
        help="Service-account client secret (overrides env LW_CLIENT_SECRET). An "
        "explicit --client-id or --client-secret beats LW_BEARER_TOKEN and "
        "LW_OFFLINE_TOKEN.",
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
        "--search",
        help="Filter by package name or group/scope (substring match).",
    )
    p_pkg.add_argument(
        "--sort-by",
        dest="sort_by",
        help="Sort by group/name, name, scope/name, or last_publication. "
        "Suffix :asc or :desc (default asc).",
    )
    p_pkg.add_argument("--repository", help="Filter by repository name.")
    p_pkg.add_argument(
        "--security-level",
        help="Filter by security level: validated, remediated, predisclosure.",
    )
    p_pkg.add_argument(
        "--demo",
        action="store_true",
        help="Return demo repositories instead of production ones.",
    )

    p_ver = sub.add_parser("package-versions", parents=[common], help="List Lightwell package versions.")
    p_ver.add_argument("--ecosystem", help="Filter by ecosystem: maven, python, npm.")
    p_ver.add_argument("--name", help="Filter by package name (substring match).")
    p_ver.add_argument(
        "--security-level",
        help="Filter by security level: validated, remediated, predisclosure.",
    )
    p_ver.add_argument(
        "--resolves-cve", dest="resolves_cve", help="Only versions that resolve this CVE ID."
    )
    p_ver.add_argument(
        "--vulnerable-to-cve",
        dest="vulnerable_to_cve",
        help="Only versions vulnerable to this CVE ID.",
    )
    p_ver.add_argument(
        "--demo",
        action="store_true",
        help="Return demo repositories instead of production ones.",
    )

    p_adv = sub.add_parser("advisories", parents=[common], help="List Lightwell security advisories.")
    p_adv.add_argument("--repository", help="Filter by repository name.")
    p_adv.add_argument("--package-name", dest="package_name", help="Package name (exact).")
    p_adv.add_argument(
        "--package-version", dest="package_version", help="Package version (exact)."
    )
    p_adv.add_argument(
        "--advisory-id",
        dest="advisory_id",
        help="Filter by advisory id (exact match).",
    )
    p_adv.add_argument(
        "--name",
        help="Deprecated. Substring match on advisory id or upstream ids.",
    )
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
    p_rpkg.add_argument(
        "--sort-by",
        dest="sort_by",
        help="Sort by name or last_updated. Suffix :asc or :desc "
        "(name defaults to asc, last_updated to desc).",
    )

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

    p_nvers = sub.add_parser(
        "npm-versions", parents=[common], help="List versions of a JavaScript package in a repository."
    )
    p_nvers.add_argument("uuid", help="Repository UUID.")
    p_nvers.add_argument(
        "scope",
        help="JS package scope (for example @types). Use - for unscoped packages.",
    )
    p_nvers.add_argument("name", help="JS package name.")

    p_ndet = sub.add_parser(
        "npm-detail", parents=[common], help="Get a specific JavaScript package version."
    )
    p_ndet.add_argument("uuid", help="Repository UUID.")
    p_ndet.add_argument(
        "scope",
        help="JS package scope (for example @types). Use - for unscoped packages.",
    )
    p_ndet.add_argument("name", help="JS package name.")
    p_ndet.add_argument("version", help="JS package upstream version.")

    sub.add_parser(
        "terms",
        parents=[common],
        help="Check whether Lightwell terms acceptance is required.",
    )

    p_subs = sub.add_parser("submissions", help="List and manage clearinghouse submissions.")
    submission_actions = p_subs.add_subparsers(dest="submission_action", required=True)
    submission_actions.add_parser(
        "list", parents=[common], help="List clearinghouse submissions."
    )
    p_sub_get = submission_actions.add_parser(
        "get", parents=[common], help="Get one clearinghouse submission."
    )
    p_sub_get.add_argument("uuid", help="Submission UUID.")
    p_sub_create = submission_actions.add_parser(
        "create",
        parents=[common],
        help="Create a submission from an intake JSON file.",
    )
    p_sub_create.add_argument(
        "--file", required=True, help="Intake JSON file. It needs a name and vulnerabilities."
    )
    p_sub_csv = submission_actions.add_parser(
        "create-csv",
        parents=[common],
        help="Create a submission from a CSV file.",
    )
    p_sub_csv.add_argument("--name", required=True, help="User-facing label, up to 255 characters.")
    p_sub_csv.add_argument("--file", required=True, help="UTF-8 CSV file of vulnerabilities.")
    p_sub_delete = submission_actions.add_parser(
        "delete", parents=[common], help="Delete a pending submission you created."
    )
    p_sub_delete.add_argument("uuid", help="Submission UUID.")
    p_sub_add = submission_actions.add_parser(
        "add-files", parents=[common], help="Add files to a pending submission."
    )
    p_sub_add.add_argument("uuid", help="Submission UUID.")
    p_sub_add.add_argument("files", nargs="+", help="Files to upload (at most 20).")
    p_sub_rm = submission_actions.add_parser(
        "delete-file", parents=[common], help="Delete one file from a pending submission."
    )
    p_sub_rm.add_argument("uuid", help="Submission UUID.")
    p_sub_rm.add_argument("filename", help="File name.")
    p_sub_dl = submission_actions.add_parser(
        "download", parents=[common], help="Download the original submission file."
    )
    p_sub_dl.add_argument("uuid", help="Submission UUID.")
    p_sub_dl.add_argument("--output", required=True, help="Path to write the file.")
    p_sub_dlf = submission_actions.add_parser(
        "download-file", parents=[common], help="Download one file from a submission."
    )
    p_sub_dlf.add_argument("uuid", help="Submission UUID.")
    p_sub_dlf.add_argument("filename", help="File name.")
    p_sub_dlf.add_argument("--output", required=True, help="Path to write the file.")
    p_sub_zip = submission_actions.add_parser(
        "archive", parents=[common], help="Download a submission and its files as a zip."
    )
    p_sub_zip.add_argument("uuid", help="Submission UUID.")
    p_sub_zip.add_argument("--output", required=True, help="Path to write the zip archive.")
    p_sub_pkgs = submission_actions.add_parser(
        "packages", parents=[common], help="List packages referenced by a submission."
    )
    p_sub_pkgs.add_argument("uuid", help="Submission UUID.")
    p_sub_pkgs.add_argument(
        "--ecosystem",
        help="Comma-separated ecosystems to include, for example Java,Unknown.",
    )
    p_sub_pkgs.add_argument(
        "--valid-purl",
        dest="valid_purl",
        choices=["true", "false"],
        help="Only packages whose package URL is valid (true) or invalid (false).",
    )
    p_sub_submit = submission_actions.add_parser(
        "submit", parents=[common], help="Submit a pending submission you created."
    )
    p_sub_submit.add_argument("uuid", help="Submission UUID.")
    p_sub_process = submission_actions.add_parser(
        "process", parents=[common], help="Mark a submitted submission as processed."
    )
    p_sub_process.add_argument("uuid", help="Submission UUID.")

    p_cov = sub.add_parser(
        "coverage-reports",
        help="Create and read Lightwell coverage reports.",
    )
    coverage_actions = p_cov.add_subparsers(dest="coverage_action", required=True)
    p_cov_create = coverage_actions.add_parser(
        "create",
        parents=[common],
        help="Upload a manifest and start coverage analysis.",
    )
    p_cov_create.add_argument(
        "--file",
        required=True,
        help="Manifest file (CycloneDX, SPDX, and other supported formats), up to 15 MiB.",
    )
    p_cov_create.add_argument(
        "--catalog-source",
        dest="catalog_source",
        choices=["pulp", "db"],
        help="Catalog used for analysis. Defaults to pulp when omitted.",
    )
    p_cov_get = coverage_actions.add_parser(
        "get", parents=[common], help="Get one coverage report."
    )
    p_cov_get.add_argument("uuid", help="Coverage report UUID.")
    p_cov_pkgs = coverage_actions.add_parser(
        "packages",
        parents=[common],
        help="List packages in a completed coverage report.",
    )
    p_cov_pkgs.add_argument("uuid", help="Coverage report UUID.")
    p_cov_pkgs.add_argument("--search", help="Filter by package name.")
    p_cov_pkgs.add_argument(
        "--ecosystem",
        help="Comma-separated ecosystems to include.",
    )
    p_cov_pkgs.add_argument(
        "--match-status",
        dest="match_status",
        help="Comma-separated match statuses: exact, partial, none.",
    )

    args = parser.parse_args()
    token = resolve_token(args)

    if args.command == "packages":
        filters = {
            "ecosystem": args.ecosystem,
            "name": args.name,
            "search": args.search,
            "sort_by": args.sort_by,
            "repository": args.repository,
            "security_level": args.security_level,
            "demo": "true" if args.demo else None,
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
            "resolves_cve": args.resolves_cve,
            "vulnerable_to_cve": args.vulnerable_to_cve,
            "demo": "true" if args.demo else None,
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
            "advisory_id": args.advisory_id,
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
            {"search": args.search, "sort_by": args.sort_by},
            args.limit,
            data_key="results",
            total_in_meta=False,
        )
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_repo_packages_table(rows)
    elif args.command == "maven-versions":
        path = f"/repositories/{_seg(args.uuid)}/java_packages/{_seg(args.group)}/{_seg(args.name)}"
        body = api_get(path, token, {})
        if args.json:
            print(json.dumps(body, indent=2))
        else:
            print_maven_versions_table(body)
    elif args.command == "maven-detail":
        path = (
            f"/repositories/{_seg(args.uuid)}/java_packages/"
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
    elif args.command == "npm-versions":
        path = (
            f"/repositories/{_seg(args.uuid)}/javascript_packages/"
            f"{_seg(args.scope)}/{_seg(args.name)}"
        )
        body = api_get(path, token, {})
        if args.json:
            print(json.dumps(body, indent=2))
        else:
            print_npm_versions_table(body)
    elif args.command == "npm-detail":
        path = (
            f"/repositories/{_seg(args.uuid)}/javascript_packages/"
            f"{_seg(args.scope)}/{_seg(args.name)}/{_seg(args.version)}"
        )
        body = api_get(path, token, {})
        if args.json:
            print(json.dumps(body, indent=2))
        else:
            print_detail(body)
    elif args.command == "terms":
        body = api_get("/terms/required", token, {})
        if args.json:
            print(json.dumps(body, indent=2))
        else:
            print_terms(body)
    elif args.command == "submissions":
        handle_submissions(args, token)
    elif args.command == "coverage-reports":
        handle_coverage_reports(args, token)


if __name__ == "__main__":
    main()

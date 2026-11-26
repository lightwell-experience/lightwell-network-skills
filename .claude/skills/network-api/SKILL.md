---
name: network-api
description: Use when asked to look up, fetch, query, or list Lightwell validated, remediated, or predisclosure package or package-version information from the console.redhat.com Lightwell Network API.
user-invocable: true
---

# Lightwell Network API Skill

Query Lightwell package and advisory data from the **Lightwell Network** API on `console.redhat.com`. This is the cross-repo view of packages Lightwell has published — filterable by ecosystem, name, and security level (validated / remediated / predisclosure).

Access requires a Red Hat identity that belongs to a group granting the **Repositories Viewer** role — either a **service account** (the recommended default) or **your own user account**. There is no pre-existing group for this — someone with permission to manage user access creates a group, assigns it the **Repositories Viewer** role, and adds the account to it. The bundled script (`scripts/fetch_lightwell_packages.py`, relative to the repo root) handles the SSO token exchange and the API calls; it has no third-party dependencies (Python stdlib only).

> **Who can manage the group:** Creating a group, assigning it a role, and adding members requires either the **Organization Administrator** or the **User Access Administrator** role. If you have neither, contact an org admin in your organization to do it (or to grant you the User Access Administrator role). If you are unsure who your org admins are, contact Red Hat technical support.

- **API base:** `https://console.redhat.com/api/lightwell/v0.1`
- **Coverage reports base:** `https://console.redhat.com/api/content-sources/v1.0` until those routes move onto the Lightwell path. The paths stay `/coverage_reports/`.
- **Endpoints used:** `GET /packages`, `GET /package_versions`, `GET /advisories`, `GET /repositories`, `GET /repositories/{uuid}/packages`, `GET /repositories/{uuid}/java_packages/{group}/{name}[/{version}]`, `GET /repositories/{uuid}/python_packages/{name}[/{version}]`, `GET /repositories/{uuid}/javascript_packages/{scope}/{name}[/{version}]`, `GET /terms/required`, the `/clearinghouse/submissions` operations (list, get, create, CSV create, files, packages, submit, process, download, archive), and `POST /coverage_reports/`, `GET /coverage_reports/{uuid}`, `GET /coverage_reports/{uuid}/packages`

### API spec

The full API specification is available in three places:

- **Red Hat API Catalog** (no auth): [https://developers.redhat.com/api-catalog/api/lightwell](https://developers.redhat.com/api-catalog/api/lightwell)
- **Hybrid Cloud Console docs** (requires auth): [https://console.redhat.com/docs/api/lightwell/v0.1](https://console.redhat.com/docs/api/lightwell/v0.1)
- **Raw OpenAPI JSON** (no auth): [https://console.redhat.com/api/lightwell/v0.1/openapi.json](https://console.redhat.com/api/lightwell/v0.1/openapi.json)

## One-time setup: service account + group

1. Create a service account in the Hybrid Cloud Console: **Settings → Service Accounts → Create service account**. Copy the **Client ID** and **Client Secret** — the secret is shown only once.
   - Full guide: [Creating and managing service accounts](https://docs.redhat.com/fr/documentation/red_hat_hybrid_cloud_console/1-latest/html-single/creating_and_managing_service_accounts/index)
2. Create a group that grants the **Repositories Viewer** role and add the service account to it. This group does not exist by default — you must create it. Without it, the API returns **403** even with a valid token. Managing the group requires the **Organization Administrator** or **User Access Administrator** role. Two cases:

   - **You have the Organization Administrator or User Access Administrator role:** create the group yourself (User Access → Groups). Name it whatever you like (e.g. **Lightwell Access**), give it the **Repositories Viewer** role, and add the service account to it.
   - **You have neither role:** contact an org admin in your organization to create a group with the **Repositories Viewer** role (or reuse an existing one) and add your service account to it — or to grant you the User Access Administrator role so you can manage it yourself. If you are unsure who your org admins are, contact Red Hat customer support.
3. Export the credentials so the script can read them:

   ```bash
   export LW_CLIENT_ID="<client-id>"
   export LW_CLIENT_SECRET="<client-secret>"
   ```

   (The legacy `CONSOLE_CLIENT_ID` / `CONSOLE_CLIENT_SECRET` names are still accepted as a fallback. Alternatively pass `--client-id` / `--client-secret`, which override the env vars. Prefer env vars — CLI flags land in shell history.)

## Alternative: authenticate as your own user account

The API only checks the `Authorization: Bearer <token>` header — it does not care whether the token belongs to a service account or to a user. Two ways to get a user-scoped token, in preference order:

**Offline token (scriptable).** Generate a personal offline token at [https://access.redhat.com/management/api](https://access.redhat.com/management/api). It is a long-lived refresh token (it expires after 30 days of non-use), which the script exchanges for a fresh access token on every run:

```bash
export LW_OFFLINE_TOKEN="<offline-token>"
python3 scripts/fetch_lightwell_packages.py packages --name jackson
```

**Existing bearer token (one-off).** If you already have an access token — e.g. copied from the `Authorization` header of an `/api/...` request in a logged-in console.redhat.com browser session — pass it through as-is. Console session tokens live only a few minutes, so this suits a single exploratory call, not a script:

```bash
export LW_BEARER_TOKEN="<access-token>"
python3 scripts/fetch_lightwell_packages.py packages --name jackson
```

Both have CLI equivalents (`--offline-token`, `--token`); `--client-id` / `--client-secret` likewise select the service account. Prefer env vars, since CLI flags land in shell history. An explicit flag beats an environment variable from a lower tier: `--offline-token` wins over a leftover `LW_BEARER_TOKEN`, and `--client-id` / `--client-secret` win over both token env vars. Within flags, then within the environment, precedence is bearer token → offline token → service-account credentials.

Two caveats:

- **Authorization is unchanged.** Your user account needs the **Repositories Viewer** role through a group just as a service account does — a user token does not bypass RBAC, you simply get the 403 under your own identity. Organization Administrators hold the role implicitly. Predisclosure remains gated by the account-level entitlement.
- **An offline token is a standing credential for your entire Red Hat account**, not a narrowly scoped one. That breadth is exactly why service accounts are the documented default; prefer one for anything automated or shared.

## How auth works

The service account authenticates with an OAuth2 **client-credentials** grant against Red Hat SSO, then calls the API with the resulting bearer token:

1. `POST https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token`
   with `grant_type=client_credentials`, `client_id`, `client_secret` → returns `access_token`.
2. `GET .../packages` with header `Authorization: Bearer <access_token>`.

The offline-token flow hits the same endpoint and realm, swapping step 1 for a refresh grant: `grant_type=refresh_token`, `client_id=rhsm-api`, `refresh_token=<offline-token>`. The resulting `access_token` carries your user identity instead of the service account's; step 2 is identical.

Core of the flow, in plain stdlib Python (the full script generalizes this):

```python
import json, urllib.parse, urllib.request

def get_token(client_id, client_secret):
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode()
    req = urllib.request.Request(
        "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
        data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with urllib.request.urlopen(req) as r:
        return json.load(r)["access_token"]

def list_packages(token, **filters):
    q = urllib.parse.urlencode({k: v for k, v in filters.items() if v})
    url = "https://console.redhat.com/api/lightwell/v0.1/packages?" + q
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)["data"]
```

## Invocation

Run the bundled script by its path relative to the repo root (from the `lightwell-skills` git directory):

```bash
python3 scripts/fetch_lightwell_packages.py <command> [filters]
```

Run with `--help` (or `<command> --help`) for the full flag list.

### `packages` — list packages (cross-repo)

```bash
python3 scripts/fetch_lightwell_packages.py packages \
    [--ecosystem maven|python|npm] [--name <substring>] [--search <substring>] \
    [--repository <repo>] [--security-level validated|remediated|predisclosure] \
    [--sort-by group/name|name|scope/name|last_publication] [--demo] [--limit N] [--json]
```

### `package-versions` — list versions with CVE filters

```bash
python3 scripts/fetch_lightwell_packages.py package-versions \
    [--ecosystem ...] [--name <substring>] [--security-level ...] \
    [--resolves-cve CVE-YYYY-NNNN] [--vulnerable-to-cve CVE-YYYY-NNNN] \
    [--demo] [--limit N] [--json]
```

### `advisories` — list security advisories

```bash
python3 scripts/fetch_lightwell_packages.py advisories \
    [--repository <repo>] [--package-name <exact>] [--package-version <exact>] \
    [--advisory-id <exact>] [--name <substring>] \
    [--severity-min low|moderate|important|critical] \
    [--cve-id CVE-YYYY-NNNN] [--latest-release] [--limit N] [--json]
```

`--advisory-id` is an exact advisory id. `--name` is deprecated: it is a substring match on the advisory id or upstream ids. `--latest-release` returns only advisories from the highest Lightwell rebuild (baseline → novel → hotfix) of a package/version, and requires `--package-name` and `--package-version`.

### `repositories` — list Lightwell repositories

```bash
python3 scripts/fetch_lightwell_packages.py repositories \
    [--search <term>] [--name <exact>] [--content-type maven|python|npm] \
    [--sort-by name|url|status] [--limit N] [--json]
```

### `repo-packages` — list packages in one repository

```bash
python3 scripts/fetch_lightwell_packages.py repo-packages <uuid> \
    [--search <term>] [--sort-by name|last_updated] [--limit N] [--json]
```

### Maven / Python / JavaScript package detail (by repository UUID)

```bash
# All versions of a Maven package
python3 scripts/fetch_lightwell_packages.py maven-versions <uuid> <group> <name> [--json]
# Builds for one Maven version
python3 scripts/fetch_lightwell_packages.py maven-detail <uuid> <group> <name> <version> [--json]

# All versions of a Python package
python3 scripts/fetch_lightwell_packages.py python-versions <uuid> <name> [--json]
# Metadata/distributions for one Python version
python3 scripts/fetch_lightwell_packages.py python-detail <uuid> <name> <version> [--json]

# All versions of a JavaScript package. <scope> is the npm scope, such as @types.
# Unscoped packages use - as the scope.
python3 scripts/fetch_lightwell_packages.py npm-versions <uuid> <scope> <name> [--json]
# Metadata for one JavaScript version
python3 scripts/fetch_lightwell_packages.py npm-detail <uuid> <scope> <name> <version> [--json]
```

Get the `<uuid>` from the `repositories` command. These detail endpoints are single-fetch (not paginated).

### `terms` — check whether Lightwell terms must be accepted

```bash
python3 scripts/fetch_lightwell_packages.py terms [--json]
```

`GET /terms/required` reports whether the current account must accept terms. When acceptance is required, the response includes the site and the event names. Other read commands return **428** until the terms are accepted at [https://console.redhat.com/lightwell](https://console.redhat.com/lightwell).

### `submissions` — clearinghouse submissions

Creating, adding files, deleting, and submitting require the **Lightwell clearinghouse** feature. Processing and downloads require **Lightwell clearinghouse read**, and the caller's username must be listed on the submission's CID. Downloads are available once the submission is submitted or processed. Each file can be at most 50 MiB, and `add-files` accepts at most 20 files.

```bash
python3 scripts/fetch_lightwell_packages.py submissions list [--limit N] [--json]
python3 scripts/fetch_lightwell_packages.py submissions get <uuid> [--json]
python3 scripts/fetch_lightwell_packages.py submissions create --file intake.json [--json]
python3 scripts/fetch_lightwell_packages.py submissions create-csv --name <label> --file vulns.csv [--json]
python3 scripts/fetch_lightwell_packages.py submissions add-files <uuid> <file> [<file> ...] [--json]
python3 scripts/fetch_lightwell_packages.py submissions delete-file <uuid> <filename>
python3 scripts/fetch_lightwell_packages.py submissions delete <uuid>
python3 scripts/fetch_lightwell_packages.py submissions submit <uuid> [--json]
python3 scripts/fetch_lightwell_packages.py submissions process <uuid> [--json]
python3 scripts/fetch_lightwell_packages.py submissions packages <uuid> \
    [--ecosystem Java,Unknown] [--valid-purl true|false] [--limit N] [--json]
python3 scripts/fetch_lightwell_packages.py submissions download <uuid> --output <path>
python3 scripts/fetch_lightwell_packages.py submissions download-file <uuid> <filename> --output <path>
python3 scripts/fetch_lightwell_packages.py submissions archive <uuid> --output <path>
```

`create` posts an intake JSON file. It needs `name` and a non-empty `vulnerabilities` array. Each vulnerability needs `vulnerability_id`, `packageurl`, `title`, and `description`. `create-csv` uses those names as the header. `vulnerability_id`, `packageurl`, `title`, and `description` are required columns. Optional columns are `component_name`, `component_version`, `cvss_severity`, `cvss_score`, `cwe`, `cvss_vector`, `exploit_tested`, `reproducer_filename`, and `customer_priority`. The CSV must be UTF-8. Deleting the original submission file deletes the whole submission. Only the user who created a pending submission can delete it, delete its files, or submit it.

### `coverage-reports` — manifest coverage

These calls use the content-sources base above and require the **Lightwell Lens** feature. They can return **428** until terms are accepted. A manifest can be at most 15 MiB. `catalog_source` defaults to `pulp`. Package rows are available once analysis has completed. The `CVES` column is `critical/important/moderate/low`.

```bash
python3 scripts/fetch_lightwell_packages.py coverage-reports create \
    --file <manifest> [--catalog-source pulp|db] [--json]
python3 scripts/fetch_lightwell_packages.py coverage-reports get <uuid> [--json]
python3 scripts/fetch_lightwell_packages.py coverage-reports packages <uuid> \
    [--search <name>] [--ecosystem <list>] [--match-status exact,partial,none] \
    [--limit N] [--json]
```

## Steps

1. **Confirm credentials exist.** The script needs one of `LW_BEARER_TOKEN`/`--token`, `LW_OFFLINE_TOKEN`/`--offline-token`, or `LW_CLIENT_ID` + `LW_CLIENT_SECRET`/`--client-id` + `--client-secret` (the legacy `CONSOLE_*` names also work). If none is set, walk the user through the one-time setup above — service account by default, or the user-account path if they prefer it.
2. **Choose the command and filters** from the user's request — `packages` for the cross-repo package view, `package-versions` for specific versions or CVE resolves/vulnerable filtering, `advisories` for security advisories (severity/CVE filtering), `repositories` to list repos, the `repo-packages` / `maven-*` / `python-*` / `npm-*` commands to drill into a single repository by UUID, `terms` to check whether terms acceptance is required, `submissions` for clearinghouse submissions, and `coverage-reports` to upload a manifest and read its coverage.
3. **Run the script.** It exchanges credentials for a token, paginates (`limit`/`offset`) automatically, and prints a table (or raw JSON with `--json`).
4. **Present results** and offer follow-ups — narrow by ecosystem/name, switch security level, drill into `package-versions`, or emit `--json` for further processing.

## Query examples

Paths are relative to the repo root (run from the `lightwell-skills` git directory):

```bash
# All remediated maven packages matching "spring"
python3 scripts/fetch_lightwell_packages.py packages --ecosystem maven --name spring --security-level remediated

# Predisclosure packages (requires the predisclosure entitlement on the account)
python3 scripts/fetch_lightwell_packages.py packages --security-level predisclosure

# Versions of spring-beans that resolve a specific CVE
python3 scripts/fetch_lightwell_packages.py package-versions --name spring-beans --resolves-cve CVE-2022-22965

# Raw JSON for scripting
python3 scripts/fetch_lightwell_packages.py packages --name jackson --json

# Critical advisories for a specific package version
python3 scripts/fetch_lightwell_packages.py advisories --package-name spring-beans --package-version 5.3.17 --severity-min critical

# List maven repositories, then drill into one
python3 scripts/fetch_lightwell_packages.py repositories --content-type maven
python3 scripts/fetch_lightwell_packages.py maven-versions <uuid> org.springframework spring-beans

# Versions of a scoped JavaScript package, then an unscoped one
python3 scripts/fetch_lightwell_packages.py npm-versions <uuid> @types is-odd
python3 scripts/fetch_lightwell_packages.py npm-versions <uuid> - left-pad
```

## Filter reference

| Filter | `packages` | `package-versions` | Notes |
|--------|:---:|:---:|-------|
| `--ecosystem` | ✓ | ✓ | `maven`, `python`, `npm` |
| `--name` | ✓ | ✓ | Substring match |
| `--security-level` | ✓ | ✓ | `validated`, `remediated`, `predisclosure` |
| `--repository` | ✓ | | Repository name |
| `--search` | ✓ | | Name or group/scope substring |
| `--sort-by` | ✓ | | `group/name`, `name`, `scope/name`, `last_publication`; optional `:asc` or `:desc` (default asc) |
| `--demo` | ✓ | ✓ | Demo repositories instead of production |
| `--resolves-cve` | | ✓ | Versions that fix this CVE |
| `--vulnerable-to-cve` | | ✓ | Versions still vulnerable to this CVE |
| `--limit` | ✓ | ✓ | Caps total results (default: all, paginated) |

`packages --sort-by` accepts those fields. `repo-packages --sort-by` accepts `name` (default asc) and `last_updated` (default desc), with the same `:asc` or `:desc` suffix.

The OpenAPI spec documents `security_level` as `validated, remediated`; `predisclosure` is also a valid level. Group/repository permissions do not control predisclosure access — it is gated separately by the **entitlement on the account**, so an account without the predisclosure entitlement will see no predisclosure data even with full repository access.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `token request failed (401/400)` | Wrong `client_id`/`client_secret`, or the secret was rotated. Recreate the service account secret and re-export. |
| `token request failed`, `invalid_grant` | The offline token is wrong or has lapsed (they expire after 30 days of non-use). Regenerate it at [access.redhat.com/management/api](https://access.redhat.com/management/api) and re-export `LW_OFFLINE_TOKEN`. |
| API returns **401** | Token invalid/expired. With service-account credentials or an offline token the script fetches a fresh token each run, so a persistent 401 means the credentials themselves are wrong. With `--token`/`LW_BEARER_TOKEN` the token is used as-is and is usually short-lived — grab a new one, or switch to one of the other two methods. |
| API returns **403** | Authenticated but not authorized. For package and repository calls, the account is not in a group with the **Repositories Viewer** role. This group is not created by default. Managing it requires the **Organization Administrator** or **User Access Administrator** role: with either, create a group with the **Repositories Viewer** role and add the account to it. With neither, ask an org admin to do so (or to grant you User Access Administrator); contact Red Hat technical support if you don't know who your org admins are. For clearinghouse calls, the account needs the **Lightwell clearinghouse** feature, or **Lightwell clearinghouse read** for process and downloads. Delete, delete-file, and submit also require the user who created the submission. Coverage reports need the **Lightwell Lens** feature. |
| API returns **428** | Lightwell terms have not been accepted. Run `terms` to see the required events, then accept them at [https://console.redhat.com/lightwell](https://console.redhat.com/lightwell). |
| `predisclosure` returns nothing | Predisclosure is gated by the **account entitlement**, not group/repository permissions — the account lacks the predisclosure entitlement. Confirm entitlement with your Lightwell administrator or Red Hat support. |
| Empty result set | Filters too narrow — drop `--security-level` or broaden `--name`, and confirm the ecosystem is right. |
</content>
</invoke>

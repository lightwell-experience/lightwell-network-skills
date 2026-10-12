---
name: network-api
description: Use when asked to look up, fetch, query, or list Lightwell validated, remediated, or predisclosure package or package-version information from the console.redhat.com Lightwell Network API.
user-invocable: true
---

# Lightwell Network API Skill

Query Lightwell package and advisory data from the **Lightwell Network** API on `console.redhat.com`. This is the cross-repo view of packages Lightwell has published — filterable by ecosystem, name, and security level (validated / remediated / predisclosure).

Access requires a **Red Hat service account** that belongs to a group granting the **Repositories Viewer** role. There is no pre-existing group for this — someone with permission to manage user access creates a group, assigns it the **Repositories Viewer** role, and adds the service account to it. The bundled script (`scripts/fetch_lightwell_packages.py`, relative to the repo root) handles the SSO token exchange and the API calls; it has no third-party dependencies (Python stdlib only).

> **Who can manage the group:** Creating a group, assigning it a role, and adding members requires either the **Organization Administrator** or the **User Access Administrator** role. If you have neither, contact an org admin in your organization to do it (or to grant you the User Access Administrator role). If you are unsure who your org admins are, contact Red Hat technical support.

- **API base:** `https://console.redhat.com/api/lightwell/v0.1`
- **Endpoints used:** `GET /packages`, `GET /package_versions`, `GET /advisories`, `GET /repositories`, `GET /repositories/{uuid}/packages`, `GET /repositories/{uuid}/maven_packages/{group}/{name}[/{version}]`, `GET /repositories/{uuid}/python_packages/{name}[/{version}]`

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

## How auth works

The service account authenticates with an OAuth2 **client-credentials** grant against Red Hat SSO, then calls the API with the resulting bearer token:

1. `POST https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token`
   with `grant_type=client_credentials`, `client_id`, `client_secret` → returns `access_token`.
2. `GET .../packages` with header `Authorization: Bearer <access_token>`.

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
    [--ecosystem maven|python|npm] [--name <substring>] \
    [--security-level validated|remediated|predisclosure] [--limit N] [--json]
```

### `package-versions` — list versions with CVE filters

```bash
python3 scripts/fetch_lightwell_packages.py package-versions \
    [--ecosystem ...] [--name <substring>] [--security-level ...] [--repository <repo>] \
    [--resolves-cve CVE-YYYY-NNNN] [--vulnerable-to-cve CVE-YYYY-NNNN] [--limit N] [--json]
```

### `advisories` — list security advisories

```bash
python3 scripts/fetch_lightwell_packages.py advisories \
    [--repository <repo>] [--package-name <exact>] [--package-version <exact>] \
    [--name <substring>] [--severity-min low|moderate|important|critical] \
    [--cve-id CVE-YYYY-NNNN] [--latest-release] [--limit N] [--json]
```

`--latest-release` returns only advisories from the highest Lightwell rebuild (baseline → novel → hotfix) of a package/version, and requires `--package-name` and `--package-version`.

### `repositories` — list Lightwell repositories

```bash
python3 scripts/fetch_lightwell_packages.py repositories \
    [--search <term>] [--name <exact>] [--content-type maven|python|npm] \
    [--sort-by name|url|status] [--limit N] [--json]
```

### `repo-packages` — list packages in one repository

```bash
python3 scripts/fetch_lightwell_packages.py repo-packages <uuid> \
    [--search <term>] [--limit N] [--json]
```

### Maven / Python package detail (by repository UUID)

```bash
# All versions of a Maven package
python3 scripts/fetch_lightwell_packages.py maven-versions <uuid> <group> <name> [--json]
# Builds for one Maven version
python3 scripts/fetch_lightwell_packages.py maven-detail <uuid> <group> <name> <version> [--json]

# All versions of a Python package
python3 scripts/fetch_lightwell_packages.py python-versions <uuid> <name> [--json]
# Metadata/distributions for one Python version
python3 scripts/fetch_lightwell_packages.py python-detail <uuid> <name> <version> [--json]
```

Get the `<uuid>` from the `repositories` command. These detail endpoints are single-fetch (not paginated).

## Steps

1. **Confirm credentials exist.** If `LW_CLIENT_ID` / `LW_CLIENT_SECRET` aren't set (nor the legacy `CONSOLE_*` fallback) and no `--client-id`/`--client-secret` given, walk the user through the one-time setup above.
2. **Choose the command and filters** from the user's request — `packages` for the cross-repo package view, `package-versions` for specific versions or CVE resolves/vulnerable filtering, `advisories` for security advisories (severity/CVE filtering), `repositories` to list repos, and the `repo-packages` / `maven-*` / `python-*` commands to drill into a single repository by UUID.
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
```

## Filter reference

| Filter | `packages` | `package-versions` | Notes |
|--------|:---:|:---:|-------|
| `--ecosystem` | ✓ | ✓ | `maven`, `python`, `npm` |
| `--name` | ✓ | ✓ | Substring match |
| `--security-level` | ✓ | ✓ | `validated`, `remediated`, `predisclosure` |
| `--repository` | | ✓ | Exact repository |
| `--resolves-cve` | | ✓ | Versions that fix this CVE |
| `--vulnerable-to-cve` | | ✓ | Versions still vulnerable to this CVE |
| `--limit` | ✓ | ✓ | Caps total results (default: all, paginated) |

The OpenAPI spec documents `security_level` as `validated, remediated`; `predisclosure` is also a valid level. Group/repository permissions do not control predisclosure access — it is gated separately by the **entitlement on the account**, so an account without the predisclosure entitlement will see no predisclosure data even with full repository access.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `token request failed (401/400)` | Wrong `client_id`/`client_secret`, or the secret was rotated. Recreate the service account secret and re-export. |
| API returns **401** | Token invalid/expired — the script fetches a fresh one each run, so a persistent 401 usually means the credentials themselves are wrong. |
| API returns **403** | Authenticated but not authorized. The service account is not in a group with the **Repositories Viewer** role. This group is not created by default. Managing it requires the **Organization Administrator** or **User Access Administrator** role: with either, create a group with the **Repositories Viewer** role and add the account to it. With neither, ask an org admin to do so (or to grant you User Access Administrator); contact Red Hat technical support if you don't know who your org admins are. |
| `predisclosure` returns nothing | Predisclosure is gated by the **account entitlement**, not group/repository permissions — the account lacks the predisclosure entitlement. Confirm entitlement with your Lightwell administrator or Red Hat support. |
| Empty result set | Filters too narrow — drop `--security-level` or broaden `--name`, and confirm the ecosystem is right. |
</content>
</invoke>

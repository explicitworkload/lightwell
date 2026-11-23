# Lightwell Network package downloader

Interactive helper to browse registry directory listings / index APIs and download selected artifacts from Red Hat [Lightwell Network](https://docs.redhat.com/en/documentation/lightwell_network/current) on `packages.redhat.com`.

> **Disclaimer:** This script is **not an officially supported Red Hat product or tool**. It is an unofficial helper that lets users interactively crawl Lightwell registry directories (and related index/Integrity endpoints) and download the packages they need. For supported day-to-day workflows, configure your build tools or on-prem repository managers (Artifactory / Nexus) per [Red Hat Lightwell Network documentation](https://docs.redhat.com/en/documentation/lightwell_network/current).

## Table of contents

- [Architecture (what talks to what)](#architecture-what-talks-to-what)
- [Capabilities](#capabilities)
- [Supported repositories](#supported-repositories)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
  - [Interactive download](#interactive-download)
  - [Provenance (auto-fetch + view / verify)](#provenance-auto-fetch--view--verify)
  - [Size estimate (HEAD only)](#size-estimate-head-only)
  - [OSV advisories (registry JSON — preferred for integrations)](#osv-advisories-registry-json--preferred-for-integrations)
  - [Catalog API (Lens / content-sources)](#catalog-api-lens--content-sources)
- [Minimal on-prem Artifactory / Nexus layout](#minimal-on-prem-artifactory--nexus-layout)
- [CLI options](#cli-options)
- [Auth quick check](#auth-quick-check)
- [Troubleshooting](#troubleshooting)
- [Not in script's scope](#not-in-scripts-scope)

## Architecture (what talks to what)

| Need | Mechanism | Auth | Script |
|---|---|---|---|
| Download packages / provenance | `packages.redhat.com` registry | Registry SA Basic Auth (`LW_USER` / `LW_TOKEN`) | `lightwell_download_python_remediated.py` |
| **Security advisories** | Pre-published **OSV JSON** under `/lightwell/osv/…` (fetch + filter locally — not a live advisory search API) | Same Registry SA | `lightwell_osv_advisories.py` |
| Catalog package/version **counts** (Lens-style) | Hybrid Console content-sources API | Hybrid Console SA Bearer (`RH_CLIENT_*`) | `lightwell_catalog_api.py` |

For integrations that need “which CVEs did Lightwell remediate for package X?”, sync the OSV trees and query the local cache. Do not rely on content-sources as a real-time advisory query API.

## Capabilities

| Capability | What it does |
|---|---|
| **Interactive browse & download** | Walk Python / Java / JavaScript Lightwell registries with Basic Auth; you pick what to open and download |
| **Repo presets** | Validated + Remediated for Python & Java; JavaScript Validated (Technology Preview) |
| **Auto provenance (Java)** | After each **main** `.jar` download, fetch `<artifact>-<version>.provenance.sigstore.json` when published |
| **Auto provenance (Python)** | After each `.whl` download, fetch PEP 740 provenance via the Pulp Integrity API (`<wheel>.provenance.json`) |
| **View / verify attestation** | Compact attestation summary; optional full JSON; `cosign` verify (PNC key 1 for Java, RELEASE3 for Python) |
| **Size estimate** | `--estimate-size`: HEAD-only `Content-Length` sample with `--filter` and `--max-artifacts` cap (not a full-catalog mirror) |
| **OSV advisories** | Separate script: sync pre-published OSV JSON from the registry, filter locally (`lightwell_osv_advisories.py`) |
| **Catalog API** | Separate script: Lens-style package/version counts via content-sources Bearer API (`lightwell_catalog_api.py`) |
| **Terminal UX** | Color on TTY (`NO_COLOR=1` to disable); step markers; post-download **Summary** (artifact + attestation notes) |

**How browsing works (not a bulk crawler):**

- **Python** — PEP 503 simple index → pick package → pick wheel/sdist → download  
- **Java** — Maven HTML directories → pick `[dir]` / `[file]` / `[attest]` → download  
- **JavaScript** — npm search/HTML (or type a name) → pick version → download `.tgz`  

The script only follows paths you select (plus one automatic provenance companion fetch when applicable). It does **not** recursively mirror an entire repository.

This talks to the **package registry** (`packages.redhat.com`, Basic Auth), not the Lightwell **content-sources API** on `console.redhat.com` (Bearer token / metadata). For catalog-scale package/version counts, use [`lightwell_catalog_api.py`](#catalog-api-lens--content-sources) below.

## Supported repositories

| Repo key | Ecosystem | Tier | Index |
|---|---|---|---|
| `python-validated` | Python | Validated | `…/python/validated/simple/` |
| `python-remediated` | Python | Remediated | `…/python/remediated/simple/` |
| `java-validated` | Java | Validated | `…/java/validated/` |
| `java-remediated` | Java | Remediated | `…/java/remediated/` |
| `javascript-validated` | JavaScript | Validated (Tech Preview) | `…/javascript/validated/` |

Docs: [Python build tools](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-configure_python_build_tool), [Java build tools](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-configure_java_build_tool), [npm client](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-configure_your_npm_client_to_use_the_lightwell_network_repository).

## Requirements

- Python 3.10+ (stdlib only — no `pip install`)
- A Lightwell Network entitlement
- A **registry** service account from [Red Hat Terms-based Registry](https://access.redhat.com/terms-based-registry)
- Optional: [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) — only for **cryptographic** provenance verify (viewing JSON needs no extra tools)

Username format: `XXXXXXX|service-account-name` (account ID, pipe, SA name — no spaces).

## Setup

```bash
export LW_USER='XXXXXXX|service-account-name'
export LW_TOKEN='your-token'
```

Credentials can also be passed with `--user` / `--token`, or entered when prompted.

## Usage

### Interactive download

```bash
python3 lightwell_download_python_remediated.py
```

You will be prompted to pick a repository, then browse packages/artifacts. Files are saved under `download/` by default.

After each download the UI prints a **Summary** with path/size and, when present, attestation notes (predicate type, subjects, builder).

```bash
# Skip the repo picker
python3 lightwell_download_python_remediated.py --repo python-remediated
python3 lightwell_download_python_remediated.py --repo java-validated
python3 lightwell_download_python_remediated.py --repo javascript-validated

# Filter lists (also used by --estimate-size)
python3 lightwell_download_python_remediated.py --repo python-remediated --filter requests
python3 lightwell_download_python_remediated.py --repo javascript-validated --filter lodash

# Custom index URL
python3 lightwell_download_python_remediated.py \
  --index-url 'https://packages.redhat.com/lightwell/python/predisclosure/simple/' \
  --kind python

# Custom output directory
python3 lightwell_download_python_remediated.py --repo java-remediated --output-dir ./artifacts
```

While browsing lists: `/text` to filter further, `q` to quit. `--kind` is optional for `--index-url` (guessed from `/python/`, `/java/`, or `/javascript/`).

### Provenance (auto-fetch + view / verify)

**Java** — On each **main** `.jar` download, automatically fetches  
`<artifactId>-<version>.provenance.sigstore.json` when published. Verify with embedded  
[PNC Provenance Signing Key 1](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-verify_provenance_for_java_artifacts).

Classifier jars (`-sources`, `-javadoc`, …) **skip** provenance download — Lightwell publishes attestation only for the main jar; the script prints a note.

**Python** — On each `.whl` download, automatically fetches PEP 740 provenance from the  
[Pulp Integrity API](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-verify_provenance_for_python_wheel_artifacts)  
as `<wheel>.provenance.json`. Verify with embedded Red Hat RELEASE3  
(`cosign verify-blob-attestation --insecure-ignore-tlog --signature …`).  
Sdists (`.tar.gz`) are not covered by that documented path.

```bash
# Offline verify / view
python3 lightwell_download_python_remediated.py \
  --verify-java download/xray-2.42.12.jar

python3 lightwell_download_python_remediated.py \
  --verify-java download/xray-2.42.12.jar \
  --bundle download/xray-2.42.12.provenance.sigstore.json

python3 lightwell_download_python_remediated.py \
  --verify-python download/sh-2.2.2+rhlw.1-1-py3-none-any.whl

python3 lightwell_download_python_remediated.py \
  --view-provenance download/xray-2.42.12.provenance.sigstore.json
```

Java Maven listings also show `[attest]` entries you can download directly.

### Size estimate (HEAD only)

Sample artifact sizes for storage planning — **not** a full-catalog mirror size:

```bash
python3 lightwell_download_python_remediated.py \
  --estimate-size --repo python-remediated --filter requests --max-artifacts 50

python3 lightwell_download_python_remediated.py \
  --estimate-size --repo java-validated --filter awssdk --max-artifacts 100
```

Uses `HEAD` (or a 1-byte ranged GET fallback) for `Content-Length`, stops at `--max-artifacts` (default 200), and prints measured total + largest samples. Prefer Artifactory/Nexus **cache growth metrics** for production disk planning.

For **Java**, `--filter` matches the artifact **name or URL path** (so `awssdk` matches jars under `…/software/amazon/awssdk/…`). Path-like filters are much faster on large Maven trees:

```bash
python3 lightwell_download_python_remediated.py \
  --estimate-size --repo java-validated \
  --filter software/amazon/awssdk --max-artifacts 20
```


### OSV advisories (registry JSON — preferred for integrations)

Lightwell publishes advisories as **OSV-format JSON files** at authenticated registry endpoints (same Terms-based Registry SA as package downloads). Sync them and filter locally:

| Tree | URL |
|---|---|
| Java remediated | `https://packages.redhat.com/lightwell/osv/java/remediated/` |
| Java predisclosure | `https://packages.redhat.com/lightwell/osv/java/predisclosure/` |
| Python remediated | `https://packages.redhat.com/lightwell/osv/python/remediated/` |
| Python predisclosure | `https://packages.redhat.com/lightwell/osv/python/predisclosure/` |

```bash
export LW_USER='XXXXXXX|service-account-name'
export LW_TOKEN='your-token'

# Download OSV JSON into download/osv/
python3 lightwell_osv_advisories.py sync --ecosystem java --tier remediated

# Local filters
python3 lightwell_osv_advisories.py list --package json-path
python3 lightwell_osv_advisories.py list --cve CVE-2023-51074 --json
python3 lightwell_osv_advisories.py show --id RHLW-2026-f8f17f4598510b8d
python3 lightwell_osv_advisories.py match --packages-file my-deps.txt

# Optional: public GitHub mirror (no registry auth)
python3 lightwell_osv_advisories.py sync --source github
```

Public mirror also used by osv.dev: [project-lightwell/lightwell-osv](https://github.com/project-lightwell/lightwell-osv).

### Catalog API (Lens / content-sources)

For **full catalog package/version counts** (what Lens shows), use a separate script against the Hybrid Console content-sources API — not the registry downloader, and not `--estimate-size`.

Per [Lightwell Network API access](https://docs.redhat.com/en/documentation/lightwell_network/current/get_started-lightwell_network_api_access):

1. Use a **Hybrid Console** service account (`console.redhat.com` → Settings → Service Accounts) — **not** the registry SA (`1234567|name`). Registry tokens are Basic Auth for `packages.redhat.com` only; they are **not** valid as `Authorization: Bearer` for `console.redhat.com/api`.
2. Put the SA in a User Access group with **Repositories viewer**.
3. Confirm `$TOKEN` is an SSO `access_token` JWT (`eyJ…`), not `$LW_TOKEN`.

```bash
# Hybrid Console SA (Get Started names CLIENT_ID / CLIENT_SECRET also work)
export CLIENT_ID='...'            # or RH_CLIENT_ID
export CLIENT_SECRET='...'        # or RH_CLIENT_SECRET

# 2) Token request — expect access_token + expires_in
curl -s https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id="$CLIENT_ID" \
  -d client_secret="$CLIENT_SECRET" \
  -d scope=api.console | jq 'keys'

export TOKEN=$(curl -s https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id="$CLIENT_ID" \
  -d client_secret="$CLIENT_SECRET" \
  -d scope=api.console | jq -r .access_token)

# 3) Sanity — list Lightwell repositories
curl -s 'https://console.redhat.com/api/content-sources/v1.0/lightwell/repositories/' \
  -H "Authorization: Bearer $TOKEN" | jq . | head -40

# Separate: org Lightwell membership via registry SA (200 = entitlement OK)
curl -s -o /dev/null -w '%{http_code}\n' -u "$LW_USER:$LW_TOKEN" \
  https://packages.redhat.com/lightwell/java/remediated/com/fasterxml/woodstox/woodstox-core/maven-metadata.xml

# Or run the same checklist in one go:
python3 lightwell_catalog_api.py doctor

# Package + version counts by ecosystem × security level (meta.count)
python3 lightwell_catalog_api.py summary

# Optional filters
python3 lightwell_catalog_api.py summary --ecosystem maven --security-level validated

# List rows (paginated)
python3 lightwell_catalog_api.py packages --ecosystem python --security-level remediated --limit 20
python3 lightwell_catalog_api.py versions --ecosystem npm --name lodash --json
# Optional metadata probe (not the preferred advisory integration path — use OSV sync)
python3 lightwell_catalog_api.py advisories --severity-min important --limit 10
```

OpenAPI: `https://console.redhat.com/api/content-sources/v1.0/openapi.json` (`/lightwell/packages`, `/lightwell/package_versions`).

## Minimal on-prem Artifactory / Nexus layout

Recommended production path: **proxy Lightwell into JFrog Artifactory or Sonatype Nexus** near consumers; point CI at the on-prem URL. Keep this script for inspection, provenance checks, and one-off downloads — not as the distribution bus.

```text
packages.redhat.com/lightwell/...
        ↑  remote proxy + registry SA (Basic Auth)
┌───────────────────────────────────────────────┐
│  Artifactory / Nexus (on-prem)                │
│                                               │
│  Remotes (examples):                          │
│    lightwell-java-validated                   │
│    lightwell-java-remediated                  │
│    lightwell-python-validated                 │
│    lightwell-python-remediated                │
│    lightwell-js-validated   (Tech Preview)    │
│                                               │
│  Virtual / group (optional precedence):       │
│    lightwell-java     → predisclosure?,       │
│                         remediated, validated │
│    lightwell-python   → same pattern          │
│    lightwell-npm      → js-validated (+ npmjs)│
└───────────────────────────────────────────────┘
        ↑
   Maven / Gradle / pip / uv / npm / CI
```

| Remote key (example) | Package type | Remote URL |
|---|---|---|
| `lightwell-java-validated` | Maven | `https://packages.redhat.com/lightwell/java/validated/` |
| `lightwell-java-remediated` | Maven | `https://packages.redhat.com/lightwell/java/remediated/` |
| `lightwell-python-validated` | PyPI | `https://packages.redhat.com/lightwell/python/validated/` (index suffix `simple`) |
| `lightwell-python-remediated` | PyPI | `https://packages.redhat.com/lightwell/python/remediated/` |
| `lightwell-js-validated` | npm | `https://packages.redhat.com/lightwell/javascript/validated` |

Auth on each remote: username `XXXXXXX|sa-name`, password = registry token. Keep the SA on the repo manager; developers/CI talk only to on-prem.

Official how-tos: [Artifactory Java](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-configure_artifactory_to_use_rhln_repository), [Nexus](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-configure_nexus_to_use_rhln_repository), [Nexus JavaScript](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-configure_nexus_for_the_lightwell_network_javascript_repository).

**Storage:** size for **cached demand**, not a full crawl. Many orgs start around **500 GB–1 TB+** for repo-manager data and grow from metrics. Use `--estimate-size` only as a filtered sample.

## CLI options

| Option | Env | Description |
|---|---|---|
| `--repo` | `LW_REPO` | Preset: `python-validated`, `python-remediated`, `java-validated`, `java-remediated`, `javascript-validated` |
| `--index-url` | `LW_INDEX_URL` | Override base URL (skips `--repo`) |
| `--kind` | — | `python`, `java`, or `javascript` when using `--index-url` |
| `--user` | `LW_USER` | Registry service account username |
| `--token` | `LW_TOKEN` | Registry service account token |
| `--output-dir` | — | Download directory (default: `download/`) |
| `--filter` | — | Substring filter for package / artifact names (browse + estimate) |
| `--estimate-size` | — | HEAD-only size sample for the selected repo |
| `--max-artifacts` | — | Cap for `--estimate-size` (default: `200`) |
| `--verify-java` | — | Local jar to verify against its provenance bundle (needs `cosign`) |
| `--verify-python` | — | Local wheel to verify against `<wheel>.provenance.json` (needs `cosign`) |
| `--bundle` | — | Provenance path for `--verify-java` / `--verify-python` |
| `--view-provenance` | — | Pretty-print a local provenance file + decoded SLSA statement |

## Auth quick check

```bash
curl -i -u "$LW_USER:$LW_TOKEN" \
  'https://packages.redhat.com/lightwell/python/remediated/simple/'
```

A successful response should be HTML with package links. `401` / `403` usually means a bad token, wrong username format, or missing entitlement.

```bash
curl -i -u "$LW_USER:$LW_TOKEN" \
  'https://packages.redhat.com/lightwell/javascript/validated/'
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `HTTP 401` / `403` | Wrong/expired token, username missing `\|`, or no Lightwell entitlement |
| `No packages found` | Wrong URL (must include `/simple/` for Python), empty filter, or entitlement issue |
| Empty Java root listing | Some Maven roots list little at the top; drill into a known group path, or pass a deeper `--index-url` |
| JavaScript list empty | Registry may not expose search/HTML listing; enter a package name when prompted |
| Provenance 404 / missing | Not published for that artifact, wrong tier URL, or (Python) package/version parse mismatch |
| No provenance for `-sources.jar` | Expected — attestation is only for the main jar; download that instead |
| Python provenance skipped for `.tar.gz` | Integrity API docs cover wheels (`.whl`) only |
| `cosign` not found | Install cosign to verify; `--view-provenance` still works without it |
| Estimate looks “too small” | Expected — `--max-artifacts` samples only; not a full catalog total |

## Not in script's scope

- Installing into an environment (`pip` / Maven / Gradle / npm) — the downloader only fetches (or HEADs) files
- Full-catalog mirroring or official Windows Server storage sizing from Red Hat
- Treating content-sources as a live advisory search API — use OSV JSON sync instead (`lightwell_osv_advisories.py`)

For day-to-day dependency resolution, configure Artifactory/Nexus (or your build tool) against Lightwell remote URLs instead of downloading by hand.

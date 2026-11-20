# Lightwell Network package downloader

Interactive helper to browse and download artifacts from Red Hat [Lightwell Network](https://docs.redhat.com/en/documentation/lightwell_network/current) registries on `packages.redhat.com`.

Supports:

| Repo key | Ecosystem | Tier | Index |
|---|---|---|---|
| `python-validated` | Python | Validated | `…/python/validated/simple/` |
| `python-remediated` | Python | Remediated | `…/python/remediated/simple/` |
| `java-validated` | Java | Validated | `…/java/validated/` |
| `java-remediated` | Java | Remediated | `…/java/remediated/` |

- **Python** — PEP 503 simple index: pick a package, then a wheel/sdist.
- **Java** — Maven layout: walk directories (`group` → `artifact` → `version`) and download `.jar` / `.pom` / etc.

This talks to the **package registry** (Basic Auth), not the Lightwell **content-sources API** on `console.redhat.com` (Bearer token / metadata). See [Configure your Python build tool](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-configure_python_build_tool) and [Configure your Java build tool](https://docs.redhat.com/en/documentation/lightwell_network/current/configure-configure_java_build_tool).

## Requirements

- Python 3.10+ (stdlib only — no `pip install`)
- A Lightwell Network entitlement
- A **registry** service account from [Red Hat Terms-based Registry](https://access.redhat.com/terms-based-registry)

Username format: `XXXXXXX|service-account-name` (account ID, pipe, SA name — no spaces).

## Setup

```bash
export LW_USER='XXXXXXX|service-account-name'
export LW_TOKEN='your-token'
```

Credentials can also be passed with `--user` / `--token`, or entered when prompted.

## Usage

```bash
python3 lightwell_download_python_remediated.py
```

You will be prompted to pick a repository, then browse packages/artifacts. Files are saved under `download/` by default.

### Skip the repo picker

```bash
python3 lightwell_download_python_remediated.py --repo python-remediated
python3 lightwell_download_python_remediated.py --repo java-validated
```

### Filter the Python package list

```bash
python3 lightwell_download_python_remediated.py --repo python-remediated --filter requests
```

While browsing lists, type `/text` to filter further, or `q` to quit.

### Custom index URL

```bash
python3 lightwell_download_python_remediated.py \
  --index-url 'https://packages.redhat.com/lightwell/python/predisclosure/simple/' \
  --kind python
```

`--kind` is optional; the script guesses from the URL path (`/python/` vs `/java/`).

### Output directory

```bash
python3 lightwell_download_python_remediated.py --repo java-remediated --output-dir ./artifacts
```

## CLI options

| Option | Env | Description |
|---|---|---|
| `--repo` | `LW_REPO` | Preset: `python-validated`, `python-remediated`, `java-validated`, `java-remediated` |
| `--index-url` | `LW_INDEX_URL` | Override base URL (skips `--repo`) |
| `--kind` | — | `python` or `java` when using `--index-url` |
| `--user` | `LW_USER` | Registry service account username |
| `--token` | `LW_TOKEN` | Registry service account token |
| `--output-dir` | — | Download directory (default: `download/`) |
| `--filter` | — | Substring filter for the Python package list |

## Auth quick check

```bash
curl -i -u "$LW_USER:$LW_TOKEN" \
  'https://packages.redhat.com/lightwell/python/remediated/simple/'
```

A successful response should be HTML with package links. `401` / `403` usually means a bad token, wrong username format, or missing entitlement.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `HTTP 401` / `403` | Wrong/expired token, username missing `\|`, or no Lightwell entitlement |
| `No packages found` | Wrong URL (must include `/simple/` for Python), empty filter, or entitlement issue |
| Empty Java root listing | Some Maven roots list little at the top; drill into a known group path, or pass a deeper `--index-url` |

## Not in scope

- Lightwell Network **API** (`console.redhat.com/api/content-sources/…`) — catalog, advisories, metadata with Bearer tokens
- Installing into an environment (`pip` / Maven / Gradle) — this script only downloads files

For day-to-day dependency resolution, configure your build tool against the same registry URLs instead of downloading by hand.

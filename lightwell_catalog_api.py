#!/usr/bin/env python3
"""
Query the Lightwell Network content-sources catalog API (console.redhat.com).

This is separate from lightwell_download_python_remediated.py:
  - Downloader  → packages.redhat.com (registry Basic Auth) — fetch binaries
  - This script → console.redhat.com/api/content-sources (Bearer token) — catalog counts/metadata

Auth (NOT the registry XXXXXXX|name / LW_TOKEN — that is Basic Auth only):
  A. Hybrid Console SA: RH_CLIENT_ID + RH_CLIENT_SECRET (scope=api.console)  [preferred]
  B. User offline token: OFFLINE_TOKEN from access.redhat.com/management/api
     (rhsm-api refresh — same path as google-apps-script/Code.gs)
  C. Short-lived Bearer: LW_API_TOKEN / ACCESS_TOKEN / TOKEN (~15 min)

  Stale $TOKEN often masks OFFLINE_TOKEN: if doctor 401s, unset TOKEN and retry.

Run with no arguments for an interactive menu, or pass a command
(summary / packages / versions / advisories / doctor).

Docs:
  https://docs.redhat.com/en/documentation/lightwell_network/current/get_started-lightwell_network_api_access

Unofficial helper — not an officially supported Red Hat product.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from zoneinfo import ZoneInfo

SGT = ZoneInfo("Asia/Singapore")
from pathlib import Path
from typing import Any

SSO_TOKEN_URL = (
    "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
)
CONSOLE_ORIGIN = "https://console.redhat.com"
API_BASE = f"{CONSOLE_ORIGIN}/api/content-sources/v1.0"
# Preferred first. SSO may still mint a token with a non-console scope that console rejects (401).
TOKEN_SCOPES = (
    "api.console",
    "openid api.console",
    "openid api.iam.service_accounts",
)

ECOSYSTEMS = ("maven", "python", "npm")
SECURITY_LEVELS = ("validated", "remediated")

# Auth probes: 401 = JWT not accepted; anything else = Bearer was accepted.
# Prefer Lightwell packages (known-good). lightwell/repositories currently returns
# HTTP 400 Bad Request even with a valid token — that is an API/path issue, not auth.
AUTH_PROBE_PATHS = (
    "/api/content-sources/v1.0/lightwell/packages?limit=1",
    "/api/content-sources/v1.0/repositories/?limit=1",
    "/api/rbac/v1/access/?application=content-sources",
    # Kept last for visibility; expect 400 until the API accepts bare GETs.
    "/api/content-sources/v1.0/lightwell/repositories/?limit=1",
)

# Registry membership check (Basic Auth) — separate from API Bearer setup.
REGISTRY_MEMBERSHIP_URL = (
    "https://packages.redhat.com/lightwell/java/remediated/"
    "com/fasterxml/woodstox/woodstox-core/maven-metadata.xml"
)


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


_USE_COLOR = _color_enabled()


def _paint(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(text: str) -> str:
    return _paint("1", text)


def dim(text: str) -> str:
    return _paint("2", text)


def green(text: str) -> str:
    return _paint("32", text)


def yellow(text: str) -> str:
    return _paint("33", text)


def cyan(text: str) -> str:
    return _paint("36", text)


def red(text: str) -> str:
    return _paint("31", text)


def ui_step(title: str) -> None:
    print()
    print(bold(cyan(f"▸ {title}")))


def ui_ok(msg: str) -> None:
    print(green(f"  ✓ {msg}"))


def ui_warn(msg: str) -> None:
    print(yellow(f"  ! {msg}"))


def ui_info(msg: str) -> None:
    print(dim(f"  · {msg}"))


def ui_err(msg: str) -> None:
    print(red(f"  ✗ {msg}"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Query Lightwell catalog via content-sources API "
            "(package / version counts and listings). "
            "Omit the command for an interactive menu."
        )
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("summary", "packages", "versions", "advisories", "doctor"),
        default=None,
        help=(
            "Optional. summary / packages / versions / advisories / doctor. "
            "Omit to open the interactive menu."
        ),
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("RH_CLIENT_ID") or os.environ.get("CLIENT_ID"),
        help="Hybrid Console SA client id. Env: RH_CLIENT_ID or CLIENT_ID",
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("RH_CLIENT_SECRET") or os.environ.get("CLIENT_SECRET"),
        help="Hybrid Console SA client secret. Env: RH_CLIENT_SECRET or CLIENT_SECRET",
    )
    parser.add_argument(
        "--token",
        default=(
            os.environ.get("LW_API_TOKEN")
            or os.environ.get("ACCESS_TOKEN")
            or os.environ.get("TOKEN")
        ),
        help=(
            "Existing Bearer access_token from SSO (skips client_credentials). "
            "Env: LW_API_TOKEN, ACCESS_TOKEN, or TOKEN — must NOT be the registry LW_TOKEN"
        ),
    )
    parser.add_argument(
        "--ecosystem",
        choices=ECOSYSTEMS,
        default=None,
        help="Filter: maven | python | npm",
    )
    parser.add_argument(
        "--security-level",
        choices=SECURITY_LEVELS,
        default=None,
        help="Filter: validated | remediated",
    )
    parser.add_argument(
        "--name",
        default="",
        help="Substring filter on package name",
    )
    parser.add_argument(
        "--search",
        default="",
        help="Broader search (packages endpoint: name/group/scope)",
    )
    parser.add_argument(
        "--repository",
        default="",
        help="Filter by repository name",
    )
    parser.add_argument(
        "--severity-min",
        default="",
        help="Advisories only: minimum severity (e.g. Important)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Page size for list commands (default: 50)",
    )
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Offset for list commands (default: 0)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print raw JSON response instead of a table",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Request demo catalog (API demo=true)",
    )
    parser.add_argument(
        "--csv",
        default="",
        help=(
            "summary: write/append rows to this CSV path "
            "(default columns: snapshot_at, ecosystem, security_level, packages, versions)"
        ),
    )
    parser.add_argument(
        "--csv-replace-day",
        action="store_true",
        help=(
            "summary + --csv: drop existing rows for today's SGT date before appending "
            "(keeps one snapshot per calendar day)"
        ),
    )
    return parser.parse_args()


def decode_jwt_claims(token: str) -> dict[str, Any]:
    """Decode JWT payload without verifying signature (diagnostic only)."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def summarize_claims(claims: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "iss",
        "aud",
        "azp",
        "scope",
        "scp",
        "typ",
        "exp",
        "preferred_username",
        "client_id",
        "username",
        "account_number",
        "account_id",
        "org_id",
        "is_org_admin",
        "is_service_account",
    )
    out: dict[str, Any] = {}
    for key in keys:
        if key in claims and claims[key] is not None:
            out[key] = claims[key]
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        try:
            out["exp_sgt"] = datetime.fromtimestamp(exp, tz=SGT).strftime(
                "%b %d, %Y %H:%M %Z"
            )
            out["expired"] = exp < datetime.now(tz=SGT).timestamp()
        except (OverflowError, OSError, ValueError):
            pass
    return out


def jwt_looks_console_capable(token: str) -> bool:
    """Heuristic: access token likely meant for console.redhat.com APIs."""
    claims = decode_jwt_claims(token)
    if not claims:
        return False
    scope = str(claims.get("scope") or claims.get("scp") or "")
    if "api.console" in scope:
        return True
    aud = claims.get("aud") or []
    if isinstance(aud, str):
        aud = [aud]
    for item in aud:
        text = str(item).lower()
        if "console" in text or "cloud-services" in text:
            return True
    return False


def jwt_is_expired(token: str) -> bool:
    claims = decode_jwt_claims(token)
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        return False
    return exp < datetime.now(tz=SGT).timestamp()


def request_sso_token(client_id: str, client_secret: str, scope: str) -> tuple[str, int]:
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        SSO_TOKEN_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "lightwell-catalog-api/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemExit(
            f"SSO token request failed for scope={scope!r}: HTTP {exc.code}\n{detail}\n"
            "Use a Hybrid Console service account (Settings → Service Accounts), "
            "not the registry XXXXXXX|name credentials."
        ) from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"SSO token request failed: {exc.reason}") from exc

    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise SystemExit(f"SSO response missing access_token: {payload!r}")
    expires = payload.get("expires_in")
    expires_i = int(expires) if isinstance(expires, int) else 0
    return token, expires_i


def request_offline_access_token(offline_token: str) -> tuple[str, int]:
    """Refresh a user offline token via client_id=rhsm-api (Apps Script AUTH_MODE=offline)."""
    body = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": "rhsm-api",
            "refresh_token": offline_token,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        SSO_TOKEN_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "lightwell-catalog-api/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemExit(
            f"SSO offline refresh failed: HTTP {exc.code}\n{detail}\n"
            "Regenerate the offline token at https://access.redhat.com/management/api"
        ) from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"SSO offline refresh failed: {exc.reason}") from exc

    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise SystemExit(f"SSO offline refresh missing access_token: {payload!r}")
    expires = payload.get("expires_in")
    expires_i = int(expires) if isinstance(expires, int) else 0
    return token, expires_i


def env_offline_token() -> str:
    return (
        os.environ.get("OFFLINE_TOKEN")
        or os.environ.get("RH_OFFLINE_TOKEN")
        or ""
    ).strip()


def http_status(url: str, token: str) -> tuple[int, str]:
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "lightwell-catalog-api/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8", errors="replace")[:200]
            return int(response.status), body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:200]
        return int(exc.code), body
    except urllib.error.URLError as exc:
        return 0, str(exc.reason)


def probe_console_accepts_token(token: str) -> tuple[bool, list[tuple[str, int]]]:
    """True if at least one console probe returns something other than 401."""
    results: list[tuple[str, int]] = []
    accepted = False
    for path in AUTH_PROBE_PATHS:
        code, _ = http_status(f"{CONSOLE_ORIGIN}{path}", token)
        results.append((path, code))
        if code and code != 401:
            accepted = True
    return accepted, results


def warn_if_registry_shaped_client_id(client_id: str) -> None:
    if "|" in client_id:
        ui_warn(
            f"RH_CLIENT_ID contains '|' ({client_id[:24]}…) — that looks like a "
            "registry SA (XXXXXXX|name), not a Hybrid Console service account."
        )
        ui_warn(
            "Create one at console.redhat.com → Settings (gear) → Service Accounts."
        )


def fetch_bearer_token(client_id: str, client_secret: str) -> str:
    warn_if_registry_shaped_client_id(client_id)
    last_token = ""
    last_scope = ""
    for scope in TOKEN_SCOPES:
        ui_info(f"SSO client_credentials scope={scope!r}")
        token, expires = request_sso_token(client_id, client_secret, scope)
        last_token, last_scope = token, scope
        claims = summarize_claims(decode_jwt_claims(token))
        scope_claim = claims.get("scope") or claims.get("scp") or "?"
        ui_ok(f"token ok (expires_in≈{expires}s, jwt.scope={scope_claim!r})")
        accepted, probes = probe_console_accepts_token(token)
        for path, code in probes:
            label = green(str(code)) if code and code != 401 else red(str(code) or "err")
            ui_info(f"probe HTTP {label}  {path}")
        if accepted:
            ui_ok(f"console accepted JWT for scope={scope!r}")
            return token
        ui_warn(f"console still returns 401 for scope={scope!r}; trying next…")

    _ = last_token  # retained for clearer exit text via last_scope
    raise SystemExit(
        "All scopes minted a token, but console.redhat.com returned 401 for each "
        f"(last scope={last_scope!r}).\n"
        "Run: python3 lightwell_catalog_api.py doctor\n"
        "Confirm RH_CLIENT_ID/SECRET are from Hybrid Console → Settings → "
        "Service Accounts (not Terms-based Registry), then add Repositories viewer."
    )


def resolve_token(args: argparse.Namespace) -> str:
    client_id = (args.client_id or "").strip()
    client_secret = (args.client_secret or "").strip()
    access = (args.token or "").strip()
    offline = env_offline_token()

    # Prefer Hybrid Console SA when configured.
    if client_id and client_secret:
        ui_info("fetching Bearer token via RH_CLIENT_ID / RH_CLIENT_SECRET")
        return fetch_bearer_token(client_id, client_secret)

    # Access token only if it looks console-capable (and not expired).
    if access and _looks_like_jwt(access):
        expired = jwt_is_expired(access)
        capable = jwt_looks_console_capable(access)
        if capable and not expired:
            ui_info("using Bearer token from --token / $LW_API_TOKEN / $TOKEN")
            return access
        if offline:
            reason = "expired" if expired else "missing api.console / console aud"
            ui_warn(
                f"$TOKEN looks unusable for content-sources ({reason}) — "
                "refreshing via $OFFLINE_TOKEN instead"
            )
        elif expired:
            raise SystemExit(
                "$TOKEN JWT is expired. unset TOKEN and use OFFLINE_TOKEN or "
                "RH_CLIENT_ID/SECRET, or mint a fresh access_token.\n"
                "Diagnose with: python3 lightwell_catalog_api.py doctor"
            )
        else:
            ui_warn(
                "$TOKEN JWT has no api.console scope — console.redhat.com often returns 401"
            )
            ui_info("using Bearer token anyway (no OFFLINE_TOKEN / SA configured)")
            return access

    if offline:
        ui_info("fetching Bearer via $OFFLINE_TOKEN (rhsm-api refresh_token)")
        token, expires = request_offline_access_token(offline)
        ui_ok(f"offline refresh ok (expires_in≈{expires}s)")
        return token

    if access:
        ui_info("using Bearer token from --token / $LW_API_TOKEN / $TOKEN")
        return access

    raise SystemExit(
        "Catalog API auth required.\n"
        "Option A — Hybrid Console service account:\n"
        "  export RH_CLIENT_ID='...'\n"
        "  export RH_CLIENT_SECRET='...'\n"
        "Option B — user offline token (same as Apps Script):\n"
        "  export OFFLINE_TOKEN='...'   # access.redhat.com/management/api\n"
        "Option C — short-lived token (~15 min):\n"
        "  export LW_API_TOKEN='...'\n"
        "\n"
        "This is different from the registry SA used by the download script "
        "(XXXXXXX|name + LW_TOKEN).\n"
        "If a stale $TOKEN is set, run: unset TOKEN LW_API_TOKEN ACCESS_TOKEN\n"
        "Diagnose with: python3 lightwell_catalog_api.py doctor"
    )


def api_get(path: str, token: str, params: dict[str, Any]) -> dict[str, Any]:
    query = {k: v for k, v in params.items() if v is not None and v != ""}
    url = f"{API_BASE}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "lightwell-catalog-api/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:800]
        hint = ""
        if exc.code == 401:
            hint = (
                "\n401 usually means the token is not accepted by console.redhat.com.\n"
                "Check: (1) SSO scope is api.console; (2) credentials are a Hybrid "
                "Console service account (not registry XXXXXXX|name); "
                "(3) the SA is in a User Access group with Repositories viewer."
            )
        elif exc.code == 403:
            hint = (
                "\n403: authenticated but forbidden — add Repositories viewer "
                "to the service account's User Access group, then fetch a fresh token."
            )
        elif exc.code == 428:
            hint = "\nLightwell terms may need to be accepted in the console."
        raise SystemExit(f"API HTTP {exc.code} for {url}\n{detail}{hint}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Failed to reach {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON from {url}: {exc}") from exc


def meta_count(payload: dict[str, Any]) -> int | None:
    meta = payload.get("meta")
    if isinstance(meta, dict) and isinstance(meta.get("count"), int):
        return meta["count"]
    return None


def build_list_params(args: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = {
        "limit": args.limit,
        "offset": args.offset,
    }
    if args.ecosystem:
        params["ecosystem"] = args.ecosystem
    if args.security_level:
        params["security_level"] = args.security_level
    if args.name:
        params["name"] = args.name
    if args.search:
        params["search"] = args.search
    if args.repository:
        params["repository"] = args.repository
    if args.demo:
        params["demo"] = "true"
    return params


CSV_FIELDS = (
    "snapshot_at",
    "ecosystem",
    "security_level",
    "packages",
    "versions",
)


def collect_summary_rows(
    token: str, args: argparse.Namespace
) -> tuple[list[dict[str, Any]], int, int]:
    """Return (rows, total_packages, total_versions) for summary probes."""
    ecosystems = (args.ecosystem,) if args.ecosystem else ECOSYSTEMS
    levels = (args.security_level,) if args.security_level else SECURITY_LEVELS
    snapshot_at = datetime.now(SGT).isoformat(timespec="seconds")
    rows: list[dict[str, Any]] = []
    total_packages = 0
    total_versions = 0

    for ecosystem in ecosystems:
        for level in levels:
            base = {
                "ecosystem": ecosystem,
                "security_level": level,
                "limit": 1,
                "offset": 0,
            }
            if args.name:
                base["name"] = args.name
            if args.search:
                base["search"] = args.search
            if args.repository:
                base["repository"] = args.repository
            if args.demo:
                base["demo"] = "true"

            packages = api_get("/lightwell/packages", token, base)
            versions = api_get("/lightwell/package_versions", token, base)
            pcount = meta_count(packages)
            vcount = meta_count(versions)
            if pcount is None or vcount is None:
                ui_warn(f"{ecosystem}/{level}: response missing meta.count")
                continue
            total_packages += pcount
            total_versions += vcount
            rows.append(
                {
                    "snapshot_at": snapshot_at,
                    "ecosystem": ecosystem,
                    "security_level": level,
                    "packages": pcount,
                    "versions": vcount,
                }
            )
    return rows, total_packages, total_versions


def write_summary_csv(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    replace_day: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: list[dict[str, str]] = []
    if path.is_file():
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                existing.append(dict(row))

    if replace_day and rows:
        today = rows[0]["snapshot_at"][:10]  # YYYY-MM-DD
        existing = [
            row
            for row in existing
            if not str(row.get("snapshot_at", "")).startswith(today)
        ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(CSV_FIELDS))
        writer.writeheader()
        for row in existing:
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})
        for row in rows:
            writer.writerow(row)


def cmd_summary(token: str, args: argparse.Namespace) -> int:
    """Print package and version counts from meta.count (limit=1 probes)."""
    ui_step("Catalog summary (meta.count)")
    ui_info("Source: GET /lightwell/packages and /lightwell/package_versions")
    print()
    header = f"{'ecosystem':<10} {'level':<12} {'packages':>10} {'versions':>10}"
    print(bold(header))
    print(dim("-" * len(header)))

    rows, total_packages, total_versions = collect_summary_rows(token, args)
    for row in rows:
        print(
            f"{row['ecosystem']:<10} {row['security_level']:<12} "
            f"{row['packages']:>10,} {row['versions']:>10,}"
        )

    print(dim("-" * len(header)))
    print(f"{'TOTAL':<10} {'(listed)':<12} {total_packages:>10,} {total_versions:>10,}")
    print()
    ui_info(
        "These are catalog package/version counts (Lens-style), not file counts "
        "(.jar/.pom/-sources) and not disk bytes."
    )

    csv_path = (args.csv or "").strip()
    if csv_path:
        out = Path(csv_path).expanduser()
        write_summary_csv(out, rows, replace_day=bool(args.csv_replace_day))
        ui_ok(f"CSV {'updated' if out.is_file() else 'written'}: {out.resolve()}")
        if args.csv_replace_day:
            ui_info("replaced any prior rows for today's SGT date, then appended")
        else:
            ui_info("appended this snapshot (use --csv-replace-day for one row-set per day)")
    return 0


def print_package_rows(payload: dict[str, Any]) -> None:
    rows = payload.get("data")
    if not isinstance(rows, list):
        ui_warn("no data[] in response")
        return
    count = meta_count(payload)
    ui_ok(f"showing {len(rows)} package(s)" + (f" of {count:,} total" if count is not None else ""))
    print()
    for row in rows:
        if not isinstance(row, dict):
            continue
        eco = row.get("ecosystem", "?")
        group = row.get("group") or ""
        name = row.get("name", "?")
        repo = row.get("repository", "")
        versions = row.get("versions") if isinstance(row.get("versions"), list) else []
        label = f"{group}:{name}" if group else str(name)
        print(f"  {cyan(str(eco)):<18} {bold(label)}")
        ui_info(f"repository={repo}  versions={len(versions)}")
        if versions:
            preview = ", ".join(str(v) for v in versions[:5])
            if len(versions) > 5:
                preview += ", …"
            ui_info(preview)


def print_version_rows(payload: dict[str, Any]) -> None:
    rows = payload.get("data")
    if not isinstance(rows, list):
        ui_warn("no data[] in response")
        return
    count = meta_count(payload)
    ui_ok(f"showing {len(rows)} version(s)" + (f" of {count:,} total" if count is not None else ""))
    print()
    for row in rows:
        if not isinstance(row, dict):
            continue
        eco = row.get("ecosystem", "?")
        coords = row.get("coordinates") or row.get("purl") or row.get("name")
        version = row.get("version", "")
        repo = row.get("repository", "")
        print(f"  {cyan(str(eco)):<18} {bold(str(coords))}  {green(str(version))}")
        ui_info(f"repository={repo}")


def print_advisory_rows(payload: dict[str, Any]) -> None:
    rows = payload.get("data")
    if not isinstance(rows, list):
        ui_warn(f"unexpected advisory shape keys={list(payload)}")
        print(json.dumps(payload, indent=2)[:4000])
        return
    count = meta_count(payload)
    ui_ok(f"showing {len(rows)} advisory row(s)" + (f" of {count:,} total" if count is not None else ""))
    print()
    for row in rows:
        if not isinstance(row, dict):
            continue
        advisory_id = row.get("advisory_id") or row.get("id") or "?"
        severity = row.get("severity") or row.get("severity_name") or ""
        title = row.get("title") or row.get("synopsis") or row.get("details") or ""
        print(f"  {bold(str(advisory_id))}  {yellow(str(severity))}")
        if title:
            ui_info(str(title)[:160])


def cmd_packages(token: str, args: argparse.Namespace) -> int:
    ui_step("List packages")
    payload = api_get("/lightwell/packages", token, build_list_params(args))
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print_package_rows(payload)
    return 0


def cmd_versions(token: str, args: argparse.Namespace) -> int:
    ui_step("List package versions")
    params = build_list_params(args)
    # versions endpoint has no "search" in OpenAPI — drop if empty already handled
    params.pop("search", None)
    payload = api_get("/lightwell/package_versions", token, params)
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print_version_rows(payload)
    return 0


def cmd_advisories(token: str, args: argparse.Namespace) -> int:
    ui_step("List advisories")
    params: dict[str, Any] = {
        "limit": args.limit,
        "offset": args.offset,
    }
    if args.severity_min:
        params["severity_min"] = args.severity_min
    payload = api_get("/lightwell/advisories", token, params)
    # OpenAPI also documents /advisories at root in docs curl — try lightwell path first.
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print_advisory_rows(payload)
    return 0


def _looks_like_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def _token_env_sanity() -> None:
    """Warn if $TOKEN / $LW_TOKEN look swapped (Get Started checklist)."""
    raw_token = (os.environ.get("TOKEN") or "").strip()
    lw_token = (os.environ.get("LW_TOKEN") or "").strip()
    lw_user = (os.environ.get("LW_USER") or "").strip()

    ui_step("1) What does $TOKEN hold?")
    if raw_token:
        if "|" in raw_token or (lw_user and raw_token == lw_user):
            ui_err("$TOKEN looks like a registry username/token — not an SSO Bearer JWT")
        elif _looks_like_jwt(raw_token):
            ui_ok(f"$TOKEN is set and looks like a JWT (len={len(raw_token)})")
        else:
            ui_warn(
                f"$TOKEN is set (len={len(raw_token)}) but does not look like a JWT "
                "(3 base64 segments). It may be the registry LW_TOKEN by mistake."
            )
    else:
        ui_info("$TOKEN unset — will use RH_CLIENT_ID/SECRET or LW_API_TOKEN if present")

    if lw_token and raw_token and lw_token == raw_token:
        ui_err(
            "$TOKEN == $LW_TOKEN — registry token is NOT valid as "
            "Authorization: Bearer for console.redhat.com/api"
        )
    if lw_user and "|" in lw_user:
        ui_info(
            f"$LW_USER looks like registry SA ({lw_user[:16]}…) — OK for "
            "packages.redhat.com Basic Auth only"
        )


def _probe_registry_membership() -> None:
    """Separate check: org Lightwell entitlement via registry Basic Auth."""
    ui_step("4) Registry membership (Basic Auth — separate from API Bearer)")
    user = (os.environ.get("LW_USER") or "").strip()
    token = (os.environ.get("LW_TOKEN") or "").strip()
    if not user or not token:
        ui_info("skip — set LW_USER + LW_TOKEN to verify packages.redhat.com entitlement")
        return
    basic = "Basic " + base64.b64encode(f"{user}:{token}".encode("utf-8")).decode(
        "ascii"
    )
    request = urllib.request.Request(
        REGISTRY_MEMBERSHIP_URL,
        headers={
            "Authorization": basic,
            "User-Agent": "lightwell-catalog-api/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            code = int(response.status)
    except urllib.error.HTTPError as exc:
        code = int(exc.code)
    except urllib.error.URLError as exc:
        ui_err(f"registry unreachable: {exc.reason}")
        return
    if code == 200:
        ui_ok(
            f"HTTP {code}  packages.redhat.com …/woodstox-core/maven-metadata.xml"
        )
        ui_info(
            "Lightwell membership/entitlement looks fine — API 401s are Hybrid "
            "Console SA / Bearer setup only"
        )
    elif code in {401, 403}:
        ui_err(f"HTTP {code}  registry Basic Auth failed — check LW_USER/LW_TOKEN")
    else:
        ui_warn(f"HTTP {code}  {REGISTRY_MEMBERSHIP_URL}")


def cmd_doctor(args: argparse.Namespace) -> int:
    """Get Started checklist: Hybrid Console SA → SSO token → lightwell/repositories."""
    ui_step("Auth doctor (Get Started: Lightwell Network API access)")
    ui_info(
        "API Bearer: Hybrid Console SA (api.console) or OFFLINE_TOKEN (rhsm-api refresh)"
    )
    ui_info(
        "Registry SA (1234567|name + LW_TOKEN) is Basic Auth for packages.redhat.com only"
    )

    _token_env_sanity()

    client_id = (args.client_id or "").strip()
    client_secret = (args.client_secret or "").strip()

    ui_step("2) Collect candidate Bearer tokens")
    tokens: list[tuple[str, str]] = []
    offline = env_offline_token()

    if args.token:
        tok = args.token.strip()
        if not _looks_like_jwt(tok):
            ui_err(
                "Supplied --token / $TOKEN does not look like an SSO access_token JWT"
            )
        else:
            capable = jwt_looks_console_capable(tok)
            expired = jwt_is_expired(tok)
            if expired:
                ui_warn("pre-supplied $TOKEN JWT is expired")
            elif not capable:
                ui_warn(
                    "pre-supplied $TOKEN is rhsm-api / graphql-scoped "
                    "(no api.console) — content-sources often returns 401"
                )
            else:
                ui_ok("pre-supplied Bearer JWT looks console-capable")
            tokens.append(("pre-supplied $TOKEN / LW_API_TOKEN / --token", tok))

    if client_id and client_secret:
        warn_if_registry_shaped_client_id(client_id)
        ui_info(f"client_id length={len(client_id)}  prefix={client_id[:12]!r}…")
        for scope in TOKEN_SCOPES:
            try:
                tok, expires = request_sso_token(client_id, client_secret, scope)
            except SystemExit as exc:
                ui_err(str(exc))
                continue
            ui_ok(
                f"SSO keys ok for scope={scope!r} "
                f"(access_token + expires_in≈{expires}s)"
            )
            tokens.append((f"SA client_credentials scope={scope!r}", tok))

    if offline:
        try:
            tok, expires = request_offline_access_token(offline)
            ui_ok(f"OFFLINE_TOKEN refresh ok (expires_in≈{expires}s)")
            tokens.append(("OFFLINE_TOKEN → rhsm-api refresh_token", tok))
        except SystemExit as exc:
            ui_err(str(exc))
    else:
        ui_info("$OFFLINE_TOKEN unset — skip user offline refresh path")

    if not tokens:
        ui_err(
            "No auth candidates. Set RH_CLIENT_ID/SECRET, or OFFLINE_TOKEN, "
            "or a Bearer TOKEN from SSO"
        )
        _probe_registry_membership()
        return 1

    ui_step("3) Sanity: GET content-sources with Bearer")
    any_ok = False
    for label, token in tokens:
        print()
        print(bold(f"· {label}"))
        claims = summarize_claims(decode_jwt_claims(token))
        if not claims:
            ui_warn("could not decode JWT payload")
        else:
            print(dim(json.dumps(claims, indent=2)))
            scope_claim = str(claims.get("scope") or claims.get("scp") or "")
            if claims.get("expired"):
                ui_warn("JWT exp is in the past")
            if "api.console" not in scope_claim and "rhsm-api" not in str(
                claims.get("azp") or ""
            ):
                ui_warn(
                    "jwt.scope does not include api.console — console may return 401"
                )
            elif "api.console" not in scope_claim:
                ui_info(
                    "jwt.scope has no api.console (normal for rhsm-api offline refresh)"
                )
        accepted, probes = probe_console_accepts_token(token)
        for path, code in probes:
            if code == 401:
                ui_err(f"HTTP {code}  {path}")
            elif code in {200, 204}:
                ui_ok(f"HTTP {code}  {path}")
            elif code == 403:
                ui_warn(f"HTTP {code}  {path}  (auth ok; missing Repositories viewer?)")
            elif code == 400 and "lightwell/repositories" in path:
                ui_info(
                    f"HTTP {code}  {path}  (auth ok; this Lightwell path rejects "
                    "bare GET — not an auth failure)"
                )
            else:
                ui_info(f"HTTP {code}  {path}")
        if accepted:
            any_ok = True
            if any(c == 403 for _, c in probes):
                ui_warn(
                    "Token accepted but forbidden — add Repositories viewer to the "
                    "SA's User Access group, then mint a fresh token."
                )
            else:
                ui_ok("Console accepts this token — try: summary")
            break

    _probe_registry_membership()

    print()
    if any_ok:
        return 0
    ui_err("No token was accepted by console.redhat.com (all probes 401).")
    print(
        dim(
            """
Quick fix if $TOKEN is stale / wrong (common):
  unset TOKEN LW_API_TOKEN ACCESS_TOKEN
  source ./jg-prep.sh          # provides OFFLINE_TOKEN
  python3 lightwell_catalog_api.py doctor

Get Started checklist:
  1. Preferred: Hybrid Console SA at console.redhat.com → Settings → Service Accounts
     Add SA to a User Access group with Repositories viewer
     export RH_CLIENT_ID=… RH_CLIENT_SECRET=…
  2. Or user offline token (same as Apps Script):
     export OFFLINE_TOKEN=…   # https://access.redhat.com/management/api
  3. Or short-lived Bearer with scope=api.console in LW_API_TOKEN
  4. curl probe lightwell/repositories/ with Authorization: Bearer …

If registry membership probe is 200: Lightwell entitlement is fine —
only Hybrid Console / Bearer setup remains.
"""
        )
    )
    return 1


def prompt_line(label: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    raw = input(dim(f"  {label}{hint}: ")).strip()
    return raw if raw else default


def prompt_yes_no(label: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(dim(f"  {label} [{suffix}]: ")).strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def prompt_choice_menu(title: str, options: list[tuple[str, str]]) -> str:
    while True:
        print()
        print(bold(title))
        for i, (label, _) in enumerate(options, start=1):
            print(f"  {cyan(f'{i:>2}')}  {label}")
        print()
        raw = input(dim("Select (number, or q to quit): ")).strip()
        if not raw:
            continue
        if raw.lower() in {"q", "quit", "exit"}:
            raise SystemExit(yellow("Cancelled."))
        if not raw.isdigit():
            ui_warn("Enter a number, or q to quit")
            continue
        idx = int(raw)
        if 1 <= idx <= len(options):
            return options[idx - 1][1]
        ui_warn(f"Choose 1–{len(options)}")


def ensure_interactive_console_auth(args: argparse.Namespace) -> None:
    """Prompt for Hybrid Console SA if no usable auth is configured."""
    if env_offline_token():
        return
    access = (args.token or "").strip()
    if access and _looks_like_jwt(access) and (
        jwt_looks_console_capable(access) and not jwt_is_expired(access)
    ):
        return
    if (args.client_id or "").strip() and (args.client_secret or "").strip():
        return
    ui_step("Hybrid Console auth")
    ui_info("Preferred: console.redhat.com → Settings → Service Accounts + Repositories viewer")
    ui_info("Or set OFFLINE_TOKEN (access.redhat.com/management/api) — same as Apps Script")
    if not (args.client_id or "").strip():
        args.client_id = prompt_line("Client ID (CLIENT_ID / RH_CLIENT_ID, blank to skip)")
    if (args.client_id or "").strip() and not (args.client_secret or "").strip():
        args.client_secret = prompt_line("Client secret")
    if (args.client_id or "").strip() and (args.client_secret or "").strip():
        return
    if env_offline_token() or (args.token or "").strip():
        return
    raise SystemExit(
        "Auth required: RH_CLIENT_ID/SECRET, or OFFLINE_TOKEN, "
        "or TOKEN / LW_API_TOKEN with an SSO access_token.\n"
        "Diagnose with: python3 lightwell_catalog_api.py doctor"
    )


def prompt_catalog_filters(args: argparse.Namespace, *, for_summary: bool) -> None:
    eco = prompt_choice_menu(
        "Ecosystem",
        [
            ("All (maven + python + npm)", "all"),
            ("Maven / Java", "maven"),
            ("Python", "python"),
            ("npm / JavaScript", "npm"),
        ],
    )
    args.ecosystem = None if eco == "all" else eco

    level = prompt_choice_menu(
        "Security level",
        [
            ("All (validated + remediated)", "all"),
            ("Validated", "validated"),
            ("Remediated", "remediated"),
        ],
    )
    args.security_level = None if level == "all" else level

    if for_summary:
        args.name = prompt_line("Optional package name substring")
        args.search = prompt_line("Optional search (packages endpoint)")
        args.repository = prompt_line("Optional repository name filter")
        return

    args.name = prompt_line("Package name substring")
    args.search = prompt_line("Search (packages only; name/group/scope)")
    args.repository = prompt_line("Repository name filter")
    limit_raw = prompt_line("Page size (limit)", str(args.limit or 50))
    try:
        args.limit = int(limit_raw)
    except ValueError:
        args.limit = 50
    args.json = prompt_yes_no("Print raw JSON?", default=False)


def interactive_menu(args: argparse.Namespace) -> int:
    ui_info("Interactive mode — pick an action (CLI flags still work when passed)")
    ui_info(
        "Prefer lightwell_osv_advisories.py for CVE/advisory integrations "
        "(OSV JSON sync)"
    )

    cached_token: str | None = None

    while True:
        action = prompt_choice_menu(
            "What do you want to do?",
            [
                ("Catalog summary (package + version counts)", "summary"),
                ("List packages", "packages"),
                ("List package versions", "versions"),
                ("List advisories (API probe — prefer OSV script)", "advisories"),
                ("Auth doctor (Get Started checklist)", "doctor"),
                ("Quit", "quit"),
            ],
        )
        if action == "quit":
            print()
            print(dim("Done."))
            return 0

        try:
            if action == "doctor":
                ensure_interactive_console_auth(args)
                code = cmd_doctor(args)
            else:
                ensure_interactive_console_auth(args)
                if not cached_token:
                    cached_token = resolve_token(args)
                token = cached_token

                if action == "summary":
                    prompt_catalog_filters(args, for_summary=True)
                    if prompt_yes_no("Also write/append a CSV snapshot?", default=False):
                        args.csv = prompt_line(
                            "CSV path", "download/catalog-summary.csv"
                        )
                        args.csv_replace_day = prompt_yes_no(
                            "Replace today's SGT rows if already present?",
                            default=True,
                        )
                    else:
                        args.csv = ""
                        args.csv_replace_day = False
                    code = cmd_summary(token, args)
                elif action == "packages":
                    prompt_catalog_filters(args, for_summary=False)
                    code = cmd_packages(token, args)
                elif action == "versions":
                    prompt_catalog_filters(args, for_summary=False)
                    args.search = ""  # versions endpoint has no search
                    code = cmd_versions(token, args)
                elif action == "advisories":
                    ui_step("Advisories (content-sources)")
                    ui_warn(
                        "For integrations, sync OSV JSON with lightwell_osv_advisories.py"
                    )
                    args.severity_min = prompt_line(
                        "Minimum severity (e.g. important, critical)", ""
                    )
                    limit_raw = prompt_line("Page size (limit)", str(args.limit or 50))
                    try:
                        args.limit = int(limit_raw)
                    except ValueError:
                        args.limit = 50
                    args.json = prompt_yes_no("Print raw JSON?", default=False)
                    code = cmd_advisories(token, args)
                else:
                    code = 1
        except SystemExit as exc:
            code_val = exc.code
            msg = str(code_val) if code_val is not None else ""
            if code_val == 130 or "Cancelled" in msg:
                raise
            if isinstance(code_val, int):
                code = code_val
                if code != 0 and msg and msg not in {"0", "1"}:
                    ui_err(msg)
            else:
                if msg:
                    ui_err(msg)
                code = 1
            # Auth failure — drop cached token so next try re-fetches
            if code != 0:
                cached_token = None

        if code == 0:
            ui_ok("Action finished")
        again = prompt_yes_no("Back to main menu?", default=True)
        if not again:
            return code


def dispatch(args: argparse.Namespace) -> int:
    if args.command is None:
        return interactive_menu(args)
    if args.command == "doctor":
        return cmd_doctor(args)

    token = resolve_token(args)
    if args.command == "summary":
        return cmd_summary(token, args)
    if args.command == "packages":
        return cmd_packages(token, args)
    if args.command == "versions":
        return cmd_versions(token, args)
    if args.command == "advisories":
        return cmd_advisories(token, args)
    raise SystemExit(f"Unknown command: {args.command}")


def main() -> int:
    args = parse_args()
    print()
    print(bold(cyan("Lightwell catalog API")))
    print(dim("content-sources · Bearer auth · catalog counts / listings"))
    print()
    ui_warn("Unofficial helper — not an officially supported Red Hat tool")
    return dispatch(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print(yellow("Cancelled."))
        raise SystemExit(130)

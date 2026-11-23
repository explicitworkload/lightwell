#!/usr/bin/env python3
"""
Fetch Lightwell OSV-format advisory JSON from the registry and filter locally.

Architecture note
-----------------
Lightwell publishes advisories as pre-built OSV JSON files at authenticated
registry URLs (same Registry Service Account / Basic Auth as package downloads).
Integrations should sync these files and query locally — not treat content-sources
as a real-time advisory search API.

  Java remediated:      https://packages.redhat.com/lightwell/osv/java/remediated/
  Java predisclosure:   https://packages.redhat.com/lightwell/osv/java/predisclosure/
  Python remediated:    https://packages.redhat.com/lightwell/osv/python/remediated/
  Python predisclosure: https://packages.redhat.com/lightwell/osv/python/predisclosure/

Auth (registry SA — same as the downloader):
  export LW_USER='XXXXXXX|service-account-name'
  export LW_TOKEN='your-token'

Run with no arguments for an interactive menu, or pass a command (sync/list/show/match).

Public mirror (optional, no registry auth): https://github.com/project-lightwell/lightwell-osv

Unofficial helper — not an officially supported Red Hat product.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

OSV_BASES = {
    ("java", "remediated"): "https://packages.redhat.com/lightwell/osv/java/remediated/",
    ("java", "predisclosure"): "https://packages.redhat.com/lightwell/osv/java/predisclosure/",
    ("python", "remediated"): "https://packages.redhat.com/lightwell/osv/python/remediated/",
    ("python", "predisclosure"): "https://packages.redhat.com/lightwell/osv/python/predisclosure/",
}

GITHUB_RAW = "https://raw.githubusercontent.com/project-lightwell/lightwell-osv/main/advisories"
GITHUB_API_LIST = (
    "https://api.github.com/repos/project-lightwell/lightwell-osv/contents/advisories"
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


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.hrefs.append(value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sync Lightwell OSV advisory JSON from the registry (Basic Auth) "
            "and filter locally. Omit the command for an interactive menu."
        )
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("sync", "list", "show", "match"),
        default=None,
        help=(
            "Optional. sync / list / show / match. "
            "Omit to open the interactive menu."
        ),
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("LW_USER"),
        help="Registry SA username (XXXXXXX|name). Env: LW_USER",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("LW_TOKEN"),
        help="Registry SA token. Env: LW_TOKEN",
    )
    parser.add_argument(
        "--ecosystem",
        choices=("java", "python", "all"),
        default="all",
        help="Which OSV tree(s) to use (default: all)",
    )
    parser.add_argument(
        "--tier",
        choices=("remediated", "predisclosure", "all"),
        default="remediated",
        help="Repository tier (default: remediated)",
    )
    parser.add_argument(
        "--cache-dir",
        default="download/osv",
        help="Local cache directory (default: download/osv)",
    )
    parser.add_argument(
        "--source",
        choices=("registry", "github"),
        default="registry",
        help=(
            "registry = packages.redhat.com/lightwell/osv/… (Basic Auth); "
            "github = public project-lightwell/lightwell-osv mirror"
        ),
    )
    parser.add_argument(
        "--id",
        default="",
        help="Advisory id (RHLW-…) for show, or substring filter for list",
    )
    parser.add_argument(
        "--package",
        default="",
        help="Substring match on affected package name (e.g. spring-core, requests)",
    )
    parser.add_argument(
        "--cve",
        default="",
        help="Match CVE / GHSA in upstream[] or references (e.g. CVE-2023-51074)",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        help="Minimum CVSS base score (parsed from severity[].score when possible)",
    )
    parser.add_argument(
        "--packages-file",
        default="",
        help="match: text file with one package name per line",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max rows to print for list/match (default: 50; 0 = unlimited)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit matching advisories as a JSON array",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="sync: re-download even if the file already exists in cache",
    )
    return parser.parse_args()


def basic_auth_header(user: str, token: str) -> str:
    raw = f"{user}:{token}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def resolve_registry_auth(args: argparse.Namespace) -> tuple[str, str] | None:
    if args.source != "registry":
        return None
    user = (args.user or "").strip()
    token = (args.token or "").strip()
    if user and token:
        return user, token
    raise SystemExit(
        "Registry OSV sync needs the Terms-based Registry service account.\n"
        "  export LW_USER='XXXXXXX|service-account-name'\n"
        "  export LW_TOKEN='your-token'\n"
        "Or use --source github for the public lightwell-osv mirror."
    )


def http_get(
    url: str,
    *,
    auth: tuple[str, str] | None = None,
    accept: str = "application/json,text/html,*/*",
    timeout: int = 120,
) -> bytes:
    headers = {
        "User-Agent": "lightwell-osv-advisories/1.0",
        "Accept": accept,
    }
    if auth:
        headers["Authorization"] = basic_auth_header(auth[0], auth[1])
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemExit(
            f"HTTP {exc.code} fetching {url}\n{body}\n"
            "Check LW_USER/LW_TOKEN (registry SA) and Lightwell entitlement."
        ) from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Failed to reach {url}: {exc.reason}") from exc


def list_json_hrefs(index_html: str, base_url: str) -> list[str]:
    parser = LinkParser()
    try:
        parser.feed(index_html)
        hrefs = parser.hrefs or HREF_RE.findall(index_html)
    except Exception:
        hrefs = HREF_RE.findall(index_html)

    out: list[str] = []
    seen: set[str] = set()
    for href in hrefs:
        href = href.strip()
        if not href or href in ("../", "./", "#"):
            continue
        path = urllib.parse.urlsplit(href).path
        name = path.rsplit("/", 1)[-1]
        if not name.lower().endswith(".json"):
            continue
        absolute = urllib.parse.urljoin(base_url, href)
        if absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
    return sorted(out)


def selected_bases(ecosystem: str, tier: str) -> list[tuple[str, str, str]]:
    """Return (eco, tier, url) triples."""
    ecos = ("java", "python") if ecosystem == "all" else (ecosystem,)
    tiers = ("remediated", "predisclosure") if tier == "all" else (tier,)
    rows: list[tuple[str, str, str]] = []
    for eco in ecos:
        for t in tiers:
            url = OSV_BASES.get((eco, t))
            if url:
                rows.append((eco, t, url))
    return rows


def cache_path(cache_dir: Path, eco: str, tier: str, filename: str) -> Path:
    return cache_dir / eco / tier / filename


def sync_registry(
    cache_dir: Path,
    auth: tuple[str, str],
    bases: list[tuple[str, str, str]],
    *,
    force: bool,
) -> int:
    total = 0
    for eco, tier, base in bases:
        ui_step(f"Sync {eco}/{tier}")
        ui_info(base)
        html = http_get(base, auth=auth, accept="text/html,*/*").decode(
            "utf-8", errors="replace"
        )
        urls = list_json_hrefs(html, base)
        if not urls:
            ui_warn("no .json links found in directory listing")
            continue
        ui_ok(f"{len(urls)} advisory file(s) listed")
        dest_dir = cache_dir / eco / tier
        dest_dir.mkdir(parents=True, exist_ok=True)
        for url in urls:
            name = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
            dest = dest_dir / name
            if dest.exists() and not force:
                continue
            data = http_get(url, auth=auth, accept="application/json")
            dest.write_bytes(data)
            total += 1
            if total % 25 == 0:
                ui_info(f"downloaded {total} new file(s)…")
        ui_ok(f"{eco}/{tier} cache → {dest_dir}")
    return total


def sync_github(cache_dir: Path, *, force: bool) -> int:
    """Pull public advisories/ tree (ecosystem inferred from each record)."""
    ui_step("Sync from GitHub lightwell-osv")
    ui_info(GITHUB_API_LIST)
    listing = json.loads(http_get(GITHUB_API_LIST, accept="application/json").decode())
    if not isinstance(listing, list):
        raise SystemExit(f"Unexpected GitHub listing shape: {type(listing)}")
    files = [
        item
        for item in listing
        if isinstance(item, dict)
        and str(item.get("name", "")).endswith(".json")
        and item.get("download_url")
    ]
    ui_ok(f"{len(files)} advisory file(s) on GitHub")
    total = 0
    for item in files:
        name = str(item["name"])
        # Stage under github/ until we know ecosystem from the record.
        staging = cache_dir / "_github" / name
        staging.parent.mkdir(parents=True, exist_ok=True)
        if staging.exists() and not force:
            path = staging
            data = path.read_bytes()
        else:
            data = http_get(str(item["download_url"]), accept="application/json")
            staging.write_bytes(data)
            total += 1
        try:
            record = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            continue
        eco, tier = infer_eco_tier(record)
        dest = cache_path(cache_dir, eco, tier, name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists() or force:
            dest.write_bytes(data)
    ui_ok(f"GitHub advisories cached under {cache_dir}")
    return total


def infer_eco_tier(record: dict[str, Any]) -> tuple[str, str]:
    eco = "java"
    tier = "remediated"
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") if isinstance(affected.get("package"), dict) else {}
        ecosystem = str(pkg.get("ecosystem") or "")
        if "PyPI" in ecosystem or "python" in ecosystem.lower():
            eco = "python"
        elif "Maven" in ecosystem or "java" in ecosystem.lower():
            eco = "java"
        db = affected.get("database_specific")
        if isinstance(db, dict):
            lw = db.get("lightwell")
            if isinstance(lw, dict):
                repo = str(lw.get("repository_url") or "")
                if "predisclosure" in repo:
                    tier = "predisclosure"
                elif "remediated" in repo:
                    tier = "remediated"
    return eco, tier


def iter_cached_records(cache_dir: Path, bases: list[tuple[str, str, str]]) -> Iterable[dict[str, Any]]:
    if not bases:
        # github-only layout: walk all json under cache
        paths = sorted(cache_dir.rglob("*.json"))
    else:
        paths = []
        for eco, tier, _ in bases:
            d = cache_dir / eco / tier
            if d.is_dir():
                paths.extend(sorted(d.glob("*.json")))
    for path in paths:
        if path.name.startswith("."):
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            ui_warn(f"skip {path}: {exc}")
            continue
        if isinstance(record, dict):
            record["_cache_path"] = str(path)
            yield record


def cvss_base_score(record: dict[str, Any]) -> float | None:
    """Best-effort parse of CVSS vector / numeric severity."""
    severities = record.get("severity")
    if not isinstance(severities, list):
        return None
    best: float | None = None
    for item in severities:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        if isinstance(score, (int, float)):
            best = max(best or 0.0, float(score))
            continue
        if not isinstance(score, str):
            continue
        # CVSS:3.1/AV:N/... — no base number embedded; try database_specific
        # Some records may use "7.5" as score string
        try:
            best = max(best or 0.0, float(score))
            continue
        except ValueError:
            pass
    # Fall back to common database_specific fields if present
    db = record.get("database_specific")
    if isinstance(db, dict):
        for key in ("severity_score", "cvss_score", "score"):
            val = db.get(key)
            if isinstance(val, (int, float)):
                best = max(best or 0.0, float(val))
    return best


def advisory_matches(
    record: dict[str, Any],
    *,
    id_substr: str,
    package: str,
    cve: str,
    min_score: float | None,
) -> bool:
    if id_substr:
        rid = str(record.get("id") or "")
        if id_substr.lower() not in rid.lower():
            return False

    if package:
        needle = package.lower()
        found = False
        for affected in record.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            pkg = affected.get("package") if isinstance(affected.get("package"), dict) else {}
            name = str(pkg.get("name") or "")
            purl = str(pkg.get("purl") or "")
            if needle in name.lower() or needle in purl.lower():
                found = True
                break
        if not found:
            return False

    if cve:
        needle = cve.lower()
        blob_parts: list[str] = []
        upstream = record.get("upstream")
        if isinstance(upstream, list):
            blob_parts.extend(str(x) for x in upstream)
        for ref in record.get("references") or []:
            if isinstance(ref, dict):
                blob_parts.append(str(ref.get("url") or ""))
        summary = str(record.get("summary") or "") + "\n" + str(record.get("details") or "")
        blob = "\n".join(blob_parts) + "\n" + summary
        if needle not in blob.lower():
            return False

    if min_score is not None:
        score = cvss_base_score(record)
        if score is None or score < min_score:
            return False

    return True


def package_names(record: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") if isinstance(affected.get("package"), dict) else {}
        name = pkg.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    return names


def remediated_version(record: dict[str, Any]) -> str:
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        db = affected.get("database_specific")
        if isinstance(db, dict):
            lw = db.get("lightwell")
            if isinstance(lw, dict) and lw.get("remediated_version"):
                return str(lw["remediated_version"])
    return ""


def print_record_summary(record: dict[str, Any]) -> None:
    rid = str(record.get("id") or "?")
    pkgs = ", ".join(package_names(record)[:3])
    if len(package_names(record)) > 3:
        pkgs += ", …"
    rem = remediated_version(record)
    upstream = record.get("upstream") if isinstance(record.get("upstream"), list) else []
    cves = ", ".join(str(x) for x in upstream[:4])
    print(f"  {bold(rid)}")
    if pkgs:
        ui_info(f"package={pkgs}")
    if rem:
        ui_info(f"remediated={rem}")
    if cves:
        ui_info(f"upstream={cves}")
    summary = str(record.get("summary") or "").strip()
    if summary:
        ui_info(summary[:140])


def ensure_cache(
    args: argparse.Namespace,
    bases: list[tuple[str, str, str]],
    auth: tuple[str, str] | None,
) -> Path:
    cache_dir = Path(args.cache_dir)
    has_files = any((cache_dir / eco / tier).glob("*.json") for eco, tier, _ in bases) if bases else any(
        cache_dir.rglob("*.json")
    )
    if has_files:
        return cache_dir
    ui_warn(f"cache empty under {cache_dir} — running sync first")
    if args.source == "github":
        sync_github(cache_dir, force=False)
    else:
        assert auth is not None
        sync_registry(cache_dir, auth, bases, force=False)
    return cache_dir


def cmd_sync(args: argparse.Namespace) -> int:
    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    if args.source == "github":
        n = sync_github(cache_dir, force=args.force)
    else:
        auth = resolve_registry_auth(args)
        assert auth is not None
        bases = selected_bases(args.ecosystem, args.tier)
        n = sync_registry(cache_dir, auth, bases, force=args.force)
    ui_ok(f"sync complete ({n} new file(s) written)")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    bases = selected_bases(args.ecosystem, args.tier)
    auth = resolve_registry_auth(args) if args.source == "registry" else None
    cache_dir = ensure_cache(args, bases, auth)
    ui_step("Filter local OSV cache")
    matches = [
        rec
        for rec in iter_cached_records(cache_dir, bases)
        if advisory_matches(
            rec,
            id_substr=args.id,
            package=args.package,
            cve=args.cve,
            min_score=args.min_score,
        )
    ]
    ui_ok(f"{len(matches)} matching advisory(ies)")
    if args.json:
        cleaned = []
        for rec in matches:
            row = dict(rec)
            row.pop("_cache_path", None)
            cleaned.append(row)
        print(json.dumps(cleaned, indent=2))
        return 0
    limit = args.limit if args.limit > 0 else len(matches)
    for rec in matches[:limit]:
        print_record_summary(rec)
    if len(matches) > limit:
        ui_info(f"… {len(matches) - limit} more (raise --limit or use --json)")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    if not args.id:
        raise SystemExit("show requires --id RHLW-…")
    bases = selected_bases(args.ecosystem, args.tier)
    auth = resolve_registry_auth(args) if args.source == "registry" else None
    cache_dir = ensure_cache(args, bases, auth)
    needle = args.id.lower()
    for rec in iter_cached_records(cache_dir, bases):
        if str(rec.get("id") or "").lower() == needle or needle in str(rec.get("id") or "").lower():
            row = dict(rec)
            row.pop("_cache_path", None)
            print(json.dumps(row, indent=2))
            return 0
    # Try direct fetch by filename if registry
    if auth and args.source == "registry":
        filename = args.id if args.id.endswith(".json") else f"{args.id}.json"
        for eco, tier, base in bases:
            url = urllib.parse.urljoin(base, filename)
            try:
                data = http_get(url, auth=auth, accept="application/json")
            except SystemExit:
                continue
            print(data.decode("utf-8"))
            dest = cache_path(cache_dir, eco, tier, filename)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            return 0
    raise SystemExit(f"Advisory not found: {args.id}")


def load_package_needles(args: argparse.Namespace) -> list[str]:
    needles: list[str] = []
    if args.package:
        needles.append(args.package.strip())
    if args.packages_file:
        path = Path(args.packages_file)
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                needles.append(line)
    # dedupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for n in needles:
        key = n.lower()
        if key not in seen:
            seen.add(key)
            out.append(n)
    if not out:
        raise SystemExit("match requires --package and/or --packages-file")
    return out


def cmd_match(args: argparse.Namespace) -> int:
    needles = load_package_needles(args)
    bases = selected_bases(args.ecosystem, args.tier)
    auth = resolve_registry_auth(args) if args.source == "registry" else None
    cache_dir = ensure_cache(args, bases, auth)
    ui_step(f"Match {len(needles)} package name(s) against OSV cache")
    hits: list[dict[str, Any]] = []
    for rec in iter_cached_records(cache_dir, bases):
        names = [n.lower() for n in package_names(rec)]
        if any(any(needle.lower() in name for name in names) for needle in needles):
            if advisory_matches(
                rec,
                id_substr=args.id,
                package="",  # already matched via needles
                cve=args.cve,
                min_score=args.min_score,
            ):
                hits.append(rec)
    ui_ok(f"{len(hits)} advisory(ies) touch those packages")
    if args.json:
        cleaned = []
        for rec in hits:
            row = dict(rec)
            row.pop("_cache_path", None)
            cleaned.append(row)
        print(json.dumps(cleaned, indent=2))
        return 0
    limit = args.limit if args.limit > 0 else len(hits)
    for rec in hits[:limit]:
        print_record_summary(rec)
    return 0


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
    """Return the value for the chosen (label, value) option. 'q' raises SystemExit."""
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


def ensure_interactive_auth(args: argparse.Namespace) -> None:
    """Prompt for registry SA if source=registry and env/flags are empty."""
    if args.source != "registry":
        return
    if args.user and args.token:
        return
    ui_step("Registry service account")
    ui_info("Same LW_USER / LW_TOKEN as the package downloader")
    ui_info("Or pick GitHub mirror from the sync menu to skip auth")
    if not args.user:
        args.user = prompt_line("Username (XXXXXXX|name)")
    if not args.token:
        args.token = prompt_line("Token")
    if not args.user or not args.token:
        raise SystemExit(
            "Registry auth required, or use source=github for the public mirror."
        )


def prompt_scope(args: argparse.Namespace) -> None:
    args.ecosystem = prompt_choice_menu(
        "Ecosystem",
        [
            ("All (java + python)", "all"),
            ("Java / Maven", "java"),
            ("Python / PyPI", "python"),
        ],
    )
    args.tier = prompt_choice_menu(
        "Tier",
        [
            ("Remediated (default)", "remediated"),
            ("Predisclosure", "predisclosure"),
            ("All tiers", "all"),
        ],
    )


def interactive_sync(args: argparse.Namespace) -> int:
    ui_step("Sync OSV advisories")
    args.source = prompt_choice_menu(
        "Source",
        [
            ("Registry (packages.redhat.com — needs LW_USER/LW_TOKEN)", "registry"),
            ("GitHub public mirror (project-lightwell/lightwell-osv)", "github"),
        ],
    )
    if args.source == "registry":
        prompt_scope(args)
        ensure_interactive_auth(args)
    else:
        args.ecosystem = "all"
        args.tier = "remediated"
    args.force = prompt_yes_no("Re-download files that already exist?", default=False)
    return cmd_sync(args)


def interactive_list(args: argparse.Namespace) -> int:
    ui_step("List / filter advisories")
    prompt_scope(args)
    ui_info("Leave filters blank to list broadly (capped by --limit)")
    args.package = prompt_line("Package substring (e.g. json-path, spring-core)")
    args.cve = prompt_line("CVE / GHSA (e.g. CVE-2023-51074)")
    args.id = prompt_line("Advisory id substring (e.g. RHLW-2026)")
    limit_raw = prompt_line("Max rows to print", "50")
    try:
        args.limit = int(limit_raw)
    except ValueError:
        args.limit = 50
    args.json = prompt_yes_no("Print full JSON?", default=False)
    if args.source == "registry" and not (
        Path(args.cache_dir).exists()
        and any(Path(args.cache_dir).rglob("*.json"))
    ):
        ensure_interactive_auth(args)
    return cmd_list(args)


def interactive_show(args: argparse.Namespace) -> int:
    ui_step("Show one advisory")
    prompt_scope(args)
    while True:
        args.id = prompt_line("Advisory id (RHLW-…)")
        if args.id:
            break
        ui_warn("An advisory id is required")
    if args.source == "registry" and not (
        Path(args.cache_dir).exists()
        and any(Path(args.cache_dir).rglob("*.json"))
    ):
        ensure_interactive_auth(args)
    return cmd_show(args)


def interactive_match(args: argparse.Namespace) -> int:
    ui_step("Match packages against advisories")
    prompt_scope(args)
    mode = prompt_choice_menu(
        "How to supply package names?",
        [
            ("Type a package substring", "one"),
            ("Path to a text file (one name per line)", "file"),
        ],
    )
    if mode == "file":
        while True:
            args.packages_file = prompt_line("Packages file path")
            if args.packages_file and Path(args.packages_file).is_file():
                break
            ui_warn("File not found — try again")
        args.package = ""
    else:
        while True:
            args.package = prompt_line("Package substring")
            if args.package:
                break
            ui_warn("Package name required")
        args.packages_file = ""
    args.cve = prompt_line("Optional CVE filter")
    limit_raw = prompt_line("Max rows to print", "50")
    try:
        args.limit = int(limit_raw)
    except ValueError:
        args.limit = 50
    args.json = prompt_yes_no("Print full JSON?", default=False)
    if args.source == "registry" and not (
        Path(args.cache_dir).exists()
        and any(Path(args.cache_dir).rglob("*.json"))
    ):
        ensure_interactive_auth(args)
    return cmd_match(args)


def interactive_menu(args: argparse.Namespace) -> int:
    """Loop until the user quits. CLI flags remain defaults unless prompted."""
    ui_info("Interactive mode — pick an action (CLI flags still work when passed)")
    cache = Path(args.cache_dir)
    if cache.exists():
        n = sum(1 for _ in cache.rglob("*.json") if "_github" not in _.parts)
        ui_info(f"Local cache: {cache} ({n} json file(s))")
    else:
        ui_info(f"Local cache empty — choose Sync first ({cache})")

    while True:
        action = prompt_choice_menu(
            "What do you want to do?",
            [
                ("Sync OSV JSON into local cache", "sync"),
                ("List / filter advisories in the cache", "list"),
                ("Show one advisory by id (full JSON)", "show"),
                ("Match package names against advisories", "match"),
                ("Quit", "quit"),
            ],
        )
        if action == "quit":
            print()
            print(dim("Done."))
            return 0
        try:
            if action == "sync":
                code = interactive_sync(args)
            elif action == "list":
                code = interactive_list(args)
            elif action == "show":
                code = interactive_show(args)
            elif action == "match":
                code = interactive_match(args)
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
                # raise SystemExit("error text") — stay in menu
                if msg:
                    ui_err(msg)
                code = 1
        if code == 0:
            ui_ok("Action finished")
        again = prompt_yes_no("Back to main menu?", default=True)
        if not again:
            return code


def dispatch(args: argparse.Namespace) -> int:
    if args.command == "sync":
        return cmd_sync(args)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "show":
        return cmd_show(args)
    if args.command == "match":
        return cmd_match(args)
    if args.command is None:
        return interactive_menu(args)
    raise SystemExit(f"Unknown command: {args.command}")


def main() -> int:
    args = parse_args()
    print()
    print(bold(cyan("Lightwell OSV advisories")))
    print(dim("registry JSON sync · local filter · Registry SA Basic Auth"))
    print()
    ui_warn("Unofficial helper — not an officially supported Red Hat tool")
    ui_info(
        "Advisories are pre-published OSV files — sync + filter locally "
        "(not a live advisory query API)."
    )
    return dispatch(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print(yellow("Cancelled."))
        raise SystemExit(130)

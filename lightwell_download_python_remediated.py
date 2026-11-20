#!/usr/bin/env python3
"""
Interactively browse and download packages from Lightwell Network registries.

Supported repos (packages.redhat.com, Basic Auth):
  - Python Validated / Remediated  (PEP 503 simple index)
  - Java Validated / Remediated    (Maven directory layout)

Auth: Lightwell registry service account (Basic Auth).
  export LW_USER='XXXXXXX|service-account-name'
  export LW_TOKEN='your-token'

Or pass --user / --token, or enter them when prompted.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

REPOS: dict[str, dict[str, str]] = {
    "python-validated": {
        "label": "Python · Validated",
        "kind": "python",
        "url": "https://packages.redhat.com/lightwell/python/validated/simple/",
    },
    "python-remediated": {
        "label": "Python · Remediated",
        "kind": "python",
        "url": "https://packages.redhat.com/lightwell/python/remediated/simple/",
    },
    "java-validated": {
        "label": "Java · Validated",
        "kind": "java",
        "url": "https://packages.redhat.com/lightwell/java/validated/",
    },
    "java-remediated": {
        "label": "Java · Remediated",
        "kind": "java",
        "url": "https://packages.redhat.com/lightwell/java/remediated/",
    },
}

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
PYTHON_ARTIFACT_EXTS = (".whl", ".tar.gz", ".zip", ".egg")
JAVA_ARTIFACT_EXTS = (
    ".jar",
    ".pom",
    ".war",
    ".ear",
    ".aar",
    ".zip",
    ".module",
    ".xml",
)
# Skip checksum/signature sidecars in the interactive list.
JAVA_SKIP_SUFFIXES = (".md5", ".sha1", ".sha256", ".sha512", ".asc")


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
    repo_help = ", ".join(REPOS)
    parser = argparse.ArgumentParser(
        description="Browse Lightwell Network repos and download a selected package."
    )
    parser.add_argument(
        "--repo",
        choices=sorted(REPOS),
        default=os.environ.get("LW_REPO"),
        help=f"Preset repository ({repo_help}). Env: LW_REPO. Prompted if omitted.",
    )
    parser.add_argument(
        "--index-url",
        default=os.environ.get("LW_INDEX_URL"),
        help="Override index/base URL (skips --repo preset). Env: LW_INDEX_URL",
    )
    parser.add_argument(
        "--kind",
        choices=("python", "java"),
        default=None,
        help="How to browse --index-url (default: guess from URL path).",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("LW_USER"),
        help="Service account username (XXXXXXX|name). Env: LW_USER",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("LW_TOKEN"),
        help="Service account token. Env: LW_TOKEN",
    )
    parser.add_argument(
        "--output-dir",
        default="download",
        help="Directory to save the downloaded file (default: download/)",
    )
    parser.add_argument(
        "--filter",
        default="",
        help="Optional substring filter applied when listing packages (Python)",
    )
    return parser.parse_args()


def ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


def basic_auth_header(user: str, token: str) -> str:
    # Always send credentials up-front. HTTPBasicAuthHandler only retries after a
    # WWW-Authenticate challenge, and packages.redhat.com often returns a bare 401.
    raw = f"{user}:{token}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def auth_error_hint(code: int, url: str, body: str) -> str:
    lines = [
        f"HTTP {code} fetching {url}",
        "",
        "Common causes:",
        "  1. Wrong/expired service-account token (regenerate at access.redhat.com/terms-based-registry)",
        "  2. Username must be exactly: <account_id>|<sa-name>  (pipe character, no spaces)",
        "  3. Account lacks a Lightwell Network entitlement on that org",
        "  4. Token pasted with extra spaces/newlines (script now strips these)",
        "",
        "Quick check with curl:",
        '  curl -i -u "$LW_USER:$LW_TOKEN" \\',
        f"    '{url}'",
    ]
    detail = body.strip()
    if detail:
        lines.extend(["", "Server response:", detail[:500]])
    return "\n".join(lines)


def open_url(url: str, user: str, token: str, timeout: int = 60):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "lightwell-download-script/1.2",
            "Authorization": basic_auth_header(user, token),
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        },
    )
    return urllib.request.urlopen(request, timeout=timeout)


def fetch_html(url: str, user: str, token: str) -> str:
    try:
        with open_url(url, user, token, timeout=60) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        if exc.code in {401, 403}:
            raise SystemExit(auth_error_hint(exc.code, url, body)) from exc
        raise SystemExit(f"HTTP {exc.code} fetching {url}: {exc.reason}\n{body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Failed to reach {url}: {exc.reason}") from exc


def extract_links(html: str, base_url: str) -> list[tuple[str, str]]:
    """Return [(display_name, absolute_url), ...] for child links."""
    parser = LinkParser()
    parser.feed(html)
    hrefs = parser.hrefs or HREF_RE.findall(html)

    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for href in hrefs:
        href = href.strip()
        if not href or href in ("../", "./", "#"):
            continue
        # Strip query/fragment for navigation decisions; keep for download URLs.
        path_only = urllib.parse.urlsplit(href).path
        name = urllib.parse.unquote(path_only.rstrip("/").split("/")[-1] or path_only)
        if not name or name in (".", ".."):
            continue
        absolute = urllib.parse.urljoin(base_url, href)
        if absolute in seen:
            continue
        seen.add(absolute)
        results.append((name, absolute))
    return results


def prompt_choice(
    title: str,
    options: list[tuple[str, str]],
    allow_filter: bool = True,
    extra_hints: str = "",
) -> tuple[str, str]:
    if not options:
        raise SystemExit(f"No options available for: {title}")

    filtered = options
    while True:
        print()
        print(title)
        print("-" * len(title))
        for i, (name, _) in enumerate(filtered, start=1):
            print(f"  {i:>3}. {name}")
        print()
        hint = "number"
        if allow_filter:
            hint += ", /text to filter, or q to quit"
        else:
            hint += ", or q to quit"
        if extra_hints:
            hint += extra_hints
        raw = input(f"Select ({hint}): ").strip()
        if not raw:
            continue
        if raw.lower() in {"q", "quit", "exit"}:
            raise SystemExit("Cancelled.")
        if allow_filter and raw.startswith("/"):
            needle = raw[1:].strip().lower()
            filtered = [(n, u) for n, u in options if needle in n.lower()]
            if not filtered:
                print(f"No matches for '{needle}'. Showing full list again.")
                filtered = options
            continue
        if not raw.isdigit():
            print("Enter a number, or /filter text.")
            continue
        idx = int(raw)
        if 1 <= idx <= len(filtered):
            return filtered[idx - 1]
        print(f"Choose a number between 1 and {len(filtered)}.")


def ends_with_any(name: str, suffixes: tuple[str, ...]) -> bool:
    lower = name.lower()
    return any(lower.endswith(ext) for ext in suffixes)


def is_python_artifact(name: str) -> bool:
    return ends_with_any(name, PYTHON_ARTIFACT_EXTS)


def is_java_artifact(name: str) -> bool:
    if ends_with_any(name, JAVA_SKIP_SUFFIXES):
        return False
    return ends_with_any(name, JAVA_ARTIFACT_EXTS)


def looks_like_directory(name: str, url: str) -> bool:
    if url.endswith("/"):
        return True
    # Maven HTML listings often omit trailing slash on folder links.
    return not ("." in name and not name.startswith("."))


def list_python_packages(
    index_url: str, user: str, token: str, name_filter: str
) -> list[tuple[str, str]]:
    html = fetch_html(index_url, user, token)
    packages = []
    for name, url in extract_links(html, index_url):
        if is_python_artifact(name):
            continue
        packages.append((name, ensure_trailing_slash(url)))
    packages.sort(key=lambda item: item[0].lower())
    if name_filter:
        needle = name_filter.lower()
        packages = [(n, u) for n, u in packages if needle in n.lower()]
    return packages


def list_python_artifacts(package_url: str, user: str, token: str) -> list[tuple[str, str]]:
    html = fetch_html(package_url, user, token)
    artifacts = [
        (name, url) for name, url in extract_links(html, package_url) if is_python_artifact(name)
    ]
    artifacts.sort(key=lambda item: item[0].lower())
    return artifacts


def list_java_entries(dir_url: str, user: str, token: str) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return (directories, artifacts) under a Maven path."""
    html = fetch_html(dir_url, user, token)
    directories: list[tuple[str, str]] = []
    artifacts: list[tuple[str, str]] = []
    for name, url in extract_links(html, dir_url):
        if is_java_artifact(name):
            artifacts.append((name, url))
        elif looks_like_directory(name, url):
            directories.append((name + "/" if not name.endswith("/") else name, ensure_trailing_slash(url)))
        # Ignore checksum/signature and other non-artifact files.
    directories.sort(key=lambda item: item[0].lower())
    artifacts.sort(key=lambda item: item[0].lower())
    return directories, artifacts


def download_file(url: str, user: str, token: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
    if not filename:
        raise SystemExit(f"Could not derive filename from URL: {url}")
    dest = output_dir / filename

    print(f"\nDownloading URL:\n  {url}")
    print(f"Saving to:\n  {dest.resolve()}")
    try:
        with open_url(url, user, token, timeout=120) as response, open(dest, "wb") as out:
            total = response.headers.get("Content-Length")
            downloaded = 0
            chunk_size = 1024 * 64
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                out.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 // int(total)
                    print(f"\r  Progress: {downloaded}/{total} bytes ({pct}%)", end="", flush=True)
                else:
                    print(f"\r  Progress: {downloaded} bytes", end="", flush=True)
            print()
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        if exc.code in {401, 403}:
            raise SystemExit(auth_error_hint(exc.code, url, body)) from exc
        raise SystemExit(f"HTTP {exc.code} downloading {url}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Failed downloading {url}: {exc.reason}") from exc

    return dest


def resolve_credentials(user: str | None, token: str | None) -> tuple[str, str]:
    # Prefer CLI flags, then shell env (LW_USER / LW_TOKEN), then prompt.
    if not user:
        user = os.environ.get("LW_USER")
        if user:
            print("Using username from $LW_USER")
    if not token:
        token = os.environ.get("LW_TOKEN")
        if token:
            print("Using token from $LW_TOKEN")

    if not user:
        user = input("Lightwell service account username (XXXXXXX|name): ").strip()
    if not token:
        token = getpass.getpass("Lightwell service account token: ")
    user = (user or "").strip()
    token = (token or "").strip()
    if not user or not token:
        raise SystemExit(
            "Username and token are required.\n"
            "Set them once in your shell:\n"
            "  export LW_USER='XXXXXXX|service-account-name'\n"
            "  export LW_TOKEN='your-token'"
        )
    if "|" not in user:
        print(
            "Warning: username usually looks like '12345678|my-sa-name'. "
            f"Got: {user!r}"
        )
    return user, token


def guess_kind(url: str) -> str:
    path = urllib.parse.urlsplit(url).path.lower()
    if "/python/" in path or path.rstrip("/").endswith("/simple") or "/simple/" in path:
        return "python"
    if "/java/" in path:
        return "java"
    # Custom override: prefer python simple-index semantics if unsure.
    return "python"


def select_repo(args: argparse.Namespace) -> tuple[str, str, str]:
    """Return (label, kind, index_url)."""
    if args.index_url:
        url = ensure_trailing_slash(args.index_url)
        kind = args.kind or guess_kind(url)
        return f"custom ({kind})", kind, url

    repo_key = args.repo
    if not repo_key:
        options = [(meta["label"], key) for key, meta in REPOS.items()]
        _, repo_key = prompt_choice("Repositories — pick one", options, allow_filter=False)
    meta = REPOS[repo_key]
    return meta["label"], meta["kind"], ensure_trailing_slash(meta["url"])


def run_python_flow(
    index_url: str, user: str, token: str, output_dir: Path, name_filter: str
) -> int:
    print("Fetching package list...")
    packages = list_python_packages(index_url, user, token, name_filter)
    if not packages:
        raise SystemExit("No packages found (check credentials, entitlement, or --filter).")

    package_name, package_url = prompt_choice(
        f"Packages ({len(packages)} found) — pick one",
        packages,
        allow_filter=True,
    )
    print(f"\nSelected package: {package_name}")
    print(f"Package page URL: {package_url}")

    print("Fetching artifact list...")
    artifacts = list_python_artifacts(package_url, user, token)
    if not artifacts:
        raise SystemExit(f"No downloadable artifacts (.whl/.tar.gz/...) under {package_url}")

    artifact_name, artifact_url = prompt_choice(
        f"Artifacts for '{package_name}' ({len(artifacts)} found) — pick one",
        artifacts,
        allow_filter=True,
    )

    confirm = input(f"\nDownload '{artifact_name}'? [Y/n]: ").strip().lower()
    if confirm in {"n", "no"}:
        print("Cancelled.")
        return 0

    dest = download_file(artifact_url, user, token, output_dir)
    print(f"\nDone.\n  File: {dest.resolve()}\n  URL:  {artifact_url}")
    return 0


def parent_url(url: str, root_url: str) -> str | None:
    root = ensure_trailing_slash(root_url)
    current = ensure_trailing_slash(url)
    if current == root or not current.startswith(root):
        return None
    parent = urllib.parse.urljoin(current, "../")
    parent = ensure_trailing_slash(parent)
    if not parent.startswith(root):
        return root
    return parent


def run_java_flow(root_url: str, user: str, token: str, output_dir: Path) -> int:
    """Walk Maven directory listings until an artifact is chosen."""
    current = root_url
    while True:
        print(f"\nBrowsing: {current}")
        print("Fetching directory listing...")
        directories, artifacts = list_java_entries(current, user, token)

        options: list[tuple[str, str]] = []
        parent = parent_url(current, root_url)
        if parent is not None:
            options.append(("../ (up one level)", parent))
        for name, url in directories:
            options.append((f"[dir]  {name}", url))
        for name, url in artifacts:
            options.append((f"[file] {name}", url))

        if not options:
            raise SystemExit(
                f"No browsable entries under {current}\n"
                "(Maven roots may not list everything; try a known group path via --index-url.)"
            )

        label, chosen_url = prompt_choice(
            f"Entries ({len(directories)} dirs, {len(artifacts)} files)",
            options,
            allow_filter=True,
            extra_hints="",
        )

        if label.startswith("../"):
            current = chosen_url
            continue
        if label.startswith("[dir]"):
            current = ensure_trailing_slash(chosen_url)
            continue

        # File selected
        artifact_name = label.removeprefix("[file] ").strip()
        confirm = input(f"\nDownload '{artifact_name}'? [Y/n]: ").strip().lower()
        if confirm in {"n", "no"}:
            print("Cancelled download; still browsing.")
            continue

        dest = download_file(chosen_url, user, token, output_dir)
        print(f"\nDone.\n  File: {dest.resolve()}\n  URL:  {chosen_url}")
        again = input("Download another from this repo? [y/N]: ").strip().lower()
        if again in {"y", "yes"}:
            continue
        return 0


def main() -> int:
    args = parse_args()
    user, token = resolve_credentials(args.user, args.token)
    output_dir = Path(args.output_dir).expanduser()

    label, kind, index_url = select_repo(args)
    print(f"Repo: {label}")
    print(f"Index: {index_url}")
    print(f"Auth user: {user}")

    if kind == "python":
        return run_python_flow(index_url, user, token, output_dir, args.filter)
    return run_java_flow(index_url, user, token, output_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelled.")
        raise SystemExit(130)

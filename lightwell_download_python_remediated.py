#!/usr/bin/env python3
"""
Interactively browse and download packages from Lightwell Network registries.

Supported repos (packages.redhat.com, Basic Auth):
  - Python Validated / Remediated     (PEP 503 simple index)
  - Java Validated / Remediated       (Maven directory layout)
  - JavaScript Validated (Tech Preview) (npm registry)

Provenance (auto-fetched on download when published):
  - Java jars → sibling <artifact>-<version>.provenance.sigstore.json
    (verify with cosign + PNC Provenance Signing Key 1)
  - Python wheels → Pulp Integrity API PEP 740 JSON (<wheel>.provenance.json)
    (verify with cosign + Red Hat RELEASE3)

Auth: Lightwell registry service account (Basic Auth).
  export LW_USER='XXXXXXX|service-account-name'
  export LW_TOKEN='your-token'

Or pass --user / --token, or enter them when prompted.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from html.parser import HTMLParser
from pathlib import Path

# --- Terminal UI (color when stdout is a TTY; respects NO_COLOR) -----------------


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


def blue(text: str) -> str:
    return _paint("34", text)


def cyan(text: str) -> str:
    return _paint("36", text)


def red(text: str) -> str:
    return _paint("31", text)


def magenta(text: str) -> str:
    return _paint("35", text)


def ui_banner() -> None:
    print()
    print(bold(cyan("Lightwell Network downloader")))
    print(dim("Browse · download · optional provenance view / cosign verify"))
    print()


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


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} B"


def file_line(path: Path, role: str) -> str:
    size = human_size(path.stat().st_size) if path.is_file() else "?"
    return f"{role:<12} {path.name}  {dim(size)}  {dim(str(path.resolve()))}"


def attestation_summary_lines(bundle_path: Path) -> list[str]:
    """Short human-readable notes from a Java/Python provenance file."""
    lines: list[str] = []
    try:
        data = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [f"could not parse {bundle_path.name}"]

    statement = extract_attestation_statement(data)
    if not isinstance(statement, dict):
        if "attestation_bundles" in data:
            lines.append("format: PEP 740 (Python Integrity API)")
        elif "dsseEnvelope" in data or data.get("mediaType"):
            lines.append("format: sigstore / DSSE bundle (Java)")
        else:
            lines.append("format: unknown JSON provenance")
        return lines

    pred = statement.get("predicateType") or statement.get("_type")
    if pred:
        lines.append(f"type: {pred}")
    subjects = statement.get("subject")
    if isinstance(subjects, list):
        lines.append(f"subjects: {len(subjects)}")
        for subj in subjects[:3]:
            if not isinstance(subj, dict):
                continue
            name = subj.get("name")
            digests = subj.get("digest") if isinstance(subj.get("digest"), dict) else {}
            digest_bits = ", ".join(f"{k}={str(v)[:12]}…" for k, v in list(digests.items())[:2])
            if name:
                lines.append(f"subject: {name}" + (f" ({digest_bits})" if digest_bits else ""))
            elif digest_bits:
                lines.append(f"digest: {digest_bits}")
    predicate = statement.get("predicate")
    if isinstance(predicate, dict):
        builder = predicate.get("builder")
        if isinstance(builder, dict) and builder.get("id"):
            lines.append(f"builder: {builder['id']}")
        build_type = predicate.get("buildType")
        if build_type:
            lines.append(f"buildType: {build_type}")
    return lines or ["attestation present (no summary fields extracted)"]


def print_download_summary(
    *,
    artifact: Path | None = None,
    attestation: Path | None = None,
    notes: list[str] | None = None,
) -> None:
    print()
    print(bold("── Summary ──"))
    if artifact and artifact.is_file():
        print(f"  {file_line(artifact, 'Artifact')}")
    if attestation and attestation.is_file():
        print(f"  {file_line(attestation, 'Attestation')}")
        for line in attestation_summary_lines(attestation):
            print(dim(f"               {line}"))
    if notes:
        for note in notes:
            ui_info(note)
    if not artifact and not attestation and not notes:
        ui_info("nothing saved")
    print()

# PNC Provenance Signing Key 1 — from Red Hat Lightwell docs:
# https://docs.redhat.com/en/documentation/lightwell_network/current/configure-verify_provenance_for_java_artifacts
PNC_PROVENANCE_SIGNING_KEY_1 = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYFyYXLNpOXF46lNdwKgOthCsOZ0W
5Uc29eO5IQzw2PKVkdpb781AZ/sUh7dSpe3hjjTu2brbjtOH1FWhO2Mmrg==
-----END PUBLIC KEY-----
"""

# Red Hat RELEASE3 — from https://security.access.redhat.com/data/63405576.txt
# Used for Python wheel provenance (Lightwell docs).
RELEASE3_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0ASyuH2TLWvBUqPHZ4Ip
75g7EncBkgQHdJnjzxAW5KQTMh/siBoB/BoSrtiPMwnChbTCnQOIQeZuDiFnhuJ7
M/D3b7JoX0m123NcCSn67mAdjBa6Bg6kukZgCP4ZUZeESajWX/EjylFcRFOXW57p
RDCEN42J/jYlVqt+g9+Grker8Sz86H3l0tbqOdjbz/VxHYhwF0ctUMHsyVRDq2QP
tqzNXlmlMhS/PoFr6R4u/7HCn/K+LegcO2fAFOb40KvKSKKVD6lewUZErhop1CgJ
XjDtGmmO9dGMF71mf6HEfaKSdy+EE6iSF2A2Vv9QhBawMiq2kOzEiLg4nAdJT8wg
ZrMAmPCqGIsXNGZ4/Q+YTwwlce3glqb5L9tfNozEdSR9N85DESfQLQEdY3CalwKM
BT1OEhEX1wHRCU4drMOej6BNW0VtscGtHmCrs74jPezhwNT8ypkyS+T0zT4Tsy6f
VXkJ8YSHyenSzMB2Op2bvsE3grY+s74WhG9UIA6DBxcTie15NSzKwfzaoNWODcLF
p7BY8aaHE2MqFxYFX+IbjpkQRfaeQQsouDFdCkXEFVfPpbD2dk6FleaMTPuyxtIT
gjVEtGQK2qGCFGiQHFd4hfV+eCA63Jro1z0zoBM5BbIIQ3+eVFwt3AlZp5UVwr6d
secqki/yrmv3Y0dqZ9VOn3UCAwEAAQ==
-----END PUBLIC KEY-----
"""
SLSA_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
PYTHON_PROVENANCE_SUFFIX = ".provenance.json"

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
    "javascript-validated": {
        "label": "JavaScript · Validated (Tech Preview)",
        "kind": "javascript",
        "url": "https://packages.redhat.com/lightwell/javascript/validated/",
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
PROVENANCE_SUFFIX = ".provenance.sigstore.json"


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
        choices=("python", "java", "javascript"),
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
        help="Optional substring filter when listing Python/JavaScript packages",
    )
    parser.add_argument(
        "--verify-java",
        metavar="JAR",
        help="Verify a local Java jar against its provenance bundle (offline; needs cosign)",
    )
    parser.add_argument(
        "--verify-python",
        metavar="WHEEL",
        help="Verify a local Python wheel against its PEP 740 provenance JSON (offline; needs cosign)",
    )
    parser.add_argument(
        "--bundle",
        metavar="PATH",
        help=(
            "Provenance path for --verify-java / --verify-python "
            "(defaults: sibling *.provenance.sigstore.json or <wheel>.provenance.json)"
        ),
    )
    parser.add_argument(
        "--view-provenance",
        metavar="BUNDLE",
        help="Pretty-print a local Java sigstore or Python PEP 740 provenance file",
    )
    parser.add_argument(
        "--estimate-size",
        action="store_true",
        help=(
            "HEAD-only size estimate for artifacts under --repo / --index-url "
            "(respects --filter; stops at --max-artifacts). Does not download bodies."
        ),
    )
    parser.add_argument(
        "--max-artifacts",
        type=int,
        default=200,
        metavar="N",
        help="Hard cap on artifacts to HEAD during --estimate-size (default: 200)",
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


def open_url(url: str, user: str, token: str, timeout: int = 60, *, method: str = "GET"):
    request = urllib.request.Request(
        url,
        method=method,
        headers={
            "User-Agent": "lightwell-download-script/1.3",
            "Authorization": basic_auth_header(user, token),
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        },
    )
    return urllib.request.urlopen(request, timeout=timeout)


def head_content_length(url: str, user: str, token: str, *, timeout: int = 10) -> int | None:
    """Return Content-Length for size estimates. Never raises (timeouts → None).

    Prefer a 1-byte ranged GET: some Lightwell/CDN edges hang or omit length on HEAD.
    """
    try:
        size = _content_length_via_range(url, user, token, timeout=timeout)
        if size is not None:
            return size
    except SystemExit:
        raise
    except Exception:
        pass

    # Fallback HEAD (short). Swallow all probe failures.
    try:
        with open_url(url, user, token, timeout=timeout, method="HEAD") as response:
            raw = response.headers.get("Content-Length")
            if raw and raw.isdigit():
                return int(raw)
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise SystemExit(auth_error_hint(exc.code, url, _read_http_error(exc))) from exc
        return None
    except Exception:
        return None
    return None


def _content_length_via_range(
    url: str, user: str, token: str, *, timeout: int = 10
) -> int | None:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "lightwell-download-script/1.3",
            "Authorization": basic_auth_header(user, token),
            "Range": "bytes=0-0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # Content-Range: bytes 0-0/12345
            content_range = response.headers.get("Content-Range") or ""
            if "/" in content_range:
                total = content_range.rsplit("/", 1)[-1]
                if total.isdigit():
                    return int(total)
            raw = response.headers.get("Content-Length")
            if raw and raw.isdigit():
                return int(raw)
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise SystemExit(auth_error_hint(exc.code, url, _read_http_error(exc))) from exc
        return None
    except Exception:
        return None
    return None


def is_estimate_binary(name: str) -> bool:
    """Main package binaries for sizing (skip metadata, provenance, classifier jars)."""
    lower = name.lower()
    if is_provenance_bundle(name):
        return False
    if is_classifier_jar(name):
        return False
    if lower.endswith((".pom", ".xml", ".module", ".md5", ".sha1", ".sha256", ".sha512", ".asc")):
        return False
    return lower.endswith((".jar", ".war", ".ear", ".aar", ".whl", ".tar.gz", ".tgz"))


def _read_http_error(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def fetch_html(url: str, user: str, token: str) -> str:
    try:
        with open_url(url, user, token, timeout=60) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")
    except urllib.error.HTTPError as exc:
        body = _read_http_error(exc)
        if exc.code in {401, 403}:
            raise SystemExit(auth_error_hint(exc.code, url, body)) from exc
        raise SystemExit(f"HTTP {exc.code} fetching {url}: {exc.reason}\n{body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Failed to reach {url}: {exc.reason}") from exc


def fetch_json(url: str, user: str, token: str) -> object:
    try:
        with open_url(url, user, token, timeout=60) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            raw = response.read().decode(charset, errors="replace")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        body = _read_http_error(exc)
        if exc.code in {401, 403}:
            raise SystemExit(auth_error_hint(exc.code, url, body)) from exc
        raise SystemExit(f"HTTP {exc.code} fetching {url}: {exc.reason}\n{body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Failed to reach {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON from {url}: {exc}") from exc


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
        print(bold(title))
        for i, (name, _) in enumerate(filtered, start=1):
            label = name
            if name.startswith("[dir]"):
                label = blue(name)
            elif name.startswith("[attest]"):
                label = magenta(name)
            elif name.startswith("[file]"):
                label = green(name)
            elif name.startswith("../"):
                label = dim(name)
            print(f"  {cyan(f'{i:>3}')}  {label}")
        print()
        hint = "number"
        if allow_filter:
            hint += ", /text to filter, or q to quit"
        else:
            hint += ", or q to quit"
        if extra_hints:
            hint += extra_hints
        raw = input(dim(f"Select ({hint}): ")).strip()
        if not raw:
            continue
        if raw.lower() in {"q", "quit", "exit"}:
            raise SystemExit(yellow("Cancelled."))
        if allow_filter and raw.startswith("/"):
            needle = raw[1:].strip().lower()
            filtered = [(n, u) for n, u in options if needle in n.lower()]
            if not filtered:
                ui_warn(f"No matches for '{needle}' — showing full list")
                filtered = options
            continue
        if not raw.isdigit():
            ui_warn("Enter a number, or /filter text")
            continue
        idx = int(raw)
        if 1 <= idx <= len(filtered):
            return filtered[idx - 1]
        ui_warn(f"Choose a number between 1 and {len(filtered)}")


def ends_with_any(name: str, suffixes: tuple[str, ...]) -> bool:
    lower = name.lower()
    return any(lower.endswith(ext) for ext in suffixes)


def is_python_artifact(name: str) -> bool:
    return ends_with_any(name, PYTHON_ARTIFACT_EXTS)


def is_java_artifact(name: str) -> bool:
    if ends_with_any(name, JAVA_SKIP_SUFFIXES):
        return False
    if is_provenance_bundle(name):
        return False
    return ends_with_any(name, JAVA_ARTIFACT_EXTS)


def is_provenance_bundle(name: str) -> bool:
    return name.lower().endswith(PROVENANCE_SUFFIX)


# Maven classifier jars (…-sources.jar) share the main artifact's provenance:
# <artifactId>-<version>.provenance.sigstore.json — not …-sources.provenance…
MAVEN_JAR_CLASSIFIERS = (
    "-sources",
    "-javadoc",
    "-tests",
    "-test-sources",
    "-test-jar",
    "-shaded",
    "-jar-with-dependencies",
)


def jar_stem_without_classifier(jar_stem: str) -> str:
    lower = jar_stem.lower()
    for classifier in MAVEN_JAR_CLASSIFIERS:
        if lower.endswith(classifier):
            return jar_stem[: -len(classifier)]
    return jar_stem


def provenance_candidates_for_jar(jar_name: str) -> list[str]:
    """Return provenance filenames to try (exact stem first, then strip classifier)."""
    if not jar_name.lower().endswith(".jar"):
        return []
    stem = jar_name[: -len(".jar")]
    names: list[str] = [stem + PROVENANCE_SUFFIX]
    base = jar_stem_without_classifier(stem)
    if base != stem:
        names.append(base + PROVENANCE_SUFFIX)
    # Dedupe, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def provenance_name_for_jar(jar_name: str) -> str | None:
    candidates = provenance_candidates_for_jar(jar_name)
    return candidates[0] if candidates else None


def provenance_urls_for_jar(jar_url: str) -> list[tuple[str, str]]:
    """Return [(provenance_filename, absolute_url), ...] candidates for a jar URL."""
    path = urllib.parse.urlsplit(jar_url).path
    name = urllib.parse.unquote(path.rsplit("/", 1)[-1])
    return [
        (prov_name, urllib.parse.urljoin(jar_url, prov_name))
        for prov_name in provenance_candidates_for_jar(name)
    ]


def provenance_url_for_jar(jar_url: str) -> str | None:
    urls = provenance_urls_for_jar(jar_url)
    return urls[0][1] if urls else None


def default_bundle_for_jar(jar_path: Path) -> Path:
    """Prefer exact sibling, else classifier-stripped main provenance beside the jar."""
    for name in provenance_candidates_for_jar(jar_path.name):
        candidate = jar_path.with_name(name)
        if candidate.is_file():
            return candidate
    candidates = provenance_candidates_for_jar(jar_path.name)
    return jar_path.with_name(candidates[-1] if candidates else jar_path.stem + PROVENANCE_SUFFIX)


def is_classifier_jar(jar_name: str) -> bool:
    if not jar_name.lower().endswith(".jar"):
        return False
    stem = jar_name[: -len(".jar")]
    return jar_stem_without_classifier(stem) != stem


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


def list_java_entries(
    dir_url: str, user: str, token: str
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]]]:
    """Return (directories, artifacts, provenance_bundles) under a Maven path."""
    html = fetch_html(dir_url, user, token)
    directories: list[tuple[str, str]] = []
    artifacts: list[tuple[str, str]] = []
    provenance: list[tuple[str, str]] = []
    for name, url in extract_links(html, dir_url):
        if is_provenance_bundle(name):
            provenance.append((name, url))
        elif is_java_artifact(name):
            artifacts.append((name, url))
        elif looks_like_directory(name, url):
            directories.append((name + "/" if not name.endswith("/") else name, ensure_trailing_slash(url)))
        # Ignore checksum/signature and other non-artifact files.
    directories.sort(key=lambda item: item[0].lower())
    artifacts.sort(key=lambda item: item[0].lower())
    provenance.sort(key=lambda item: item[0].lower())
    return directories, artifacts, provenance


def download_file(
    url: str,
    user: str,
    token: str,
    output_dir: Path,
    *,
    optional: bool = False,
    filename: str | None = None,
) -> Path | None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not filename:
        filename = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1])
    if not filename or filename in {".", "..", "provenance"}:
        raise SystemExit(f"Could not derive filename from URL: {url}")
    dest = output_dir / filename

    print(f"  {cyan('↓')} {bold(filename)}  {dim(url)}")
    try:
        with open_url(url, user, token, timeout=120) as response, open(dest, "wb") as out:
            total_hdr = response.headers.get("Content-Length")
            total = int(total_hdr) if total_hdr and total_hdr.isdigit() else None
            downloaded = 0
            chunk_size = 1024 * 64
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                out.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 // total
                    bar = f"{pct:3d}% {human_size(downloaded)}/{human_size(total)}"
                else:
                    bar = human_size(downloaded)
                print(f"\r    {dim(bar)}", end="", flush=True)
            print()
            ui_ok(f"saved {human_size(downloaded)} → {dest.resolve()}")
    except urllib.error.HTTPError as exc:
        body = _read_http_error(exc)
        if optional and exc.code == 404:
            ui_warn(f"not found: {filename}")
            return None
        if exc.code in {401, 403}:
            raise SystemExit(auth_error_hint(exc.code, url, body)) from exc
        raise SystemExit(f"HTTP {exc.code} downloading {url}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Failed downloading {url}: {exc.reason}") from exc

    return dest


def _decode_b64_json(value: str) -> object | None:
    try:
        raw = base64.b64decode(value)
        return json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def extract_attestation_statement(bundle: object) -> object | None:
    """Best-effort extract of the in-toto / SLSA statement from Java or Python provenance."""
    if not isinstance(bundle, dict):
        return None

    # Java / cosign sigstore bundle
    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        content = bundle.get("content")
        if isinstance(content, dict):
            envelope = content.get("dsseEnvelope") or content.get("dsse_envelope")
    if isinstance(envelope, dict):
        payload_b64 = envelope.get("payload")
        if isinstance(payload_b64, str):
            decoded = _decode_b64_json(payload_b64)
            if decoded is not None:
                return decoded

    # Python PEP 740 Integrity API response
    pep_env = pep740_first_envelope(bundle)
    if pep_env is not None:
        statement = pep_env.get("statement")
        if isinstance(statement, str):
            decoded = _decode_b64_json(statement)
            if decoded is not None:
                return decoded
            # Some payloads may already be JSON text
            try:
                return json.loads(statement)
            except json.JSONDecodeError:
                return {"raw_statement": statement[:2000]}
        if isinstance(statement, dict):
            return statement
    return None


def pep740_first_envelope(provenance: object) -> dict | None:
    if not isinstance(provenance, dict):
        return None
    bundles = provenance.get("attestation_bundles")
    if not isinstance(bundles, list) or not bundles:
        return None
    first = bundles[0]
    if not isinstance(first, dict):
        return None
    attestations = first.get("attestations")
    if not isinstance(attestations, list) or not attestations:
        return None
    att = attestations[0]
    if not isinstance(att, dict):
        return None
    envelope = att.get("envelope")
    return envelope if isinstance(envelope, dict) else None


def pep740_to_dsse(provenance: object) -> dict:
    """Map PEP 740 envelope fields to a DSSE object cosign accepts via --signature."""
    envelope = pep740_first_envelope(provenance)
    if envelope is None:
        raise SystemExit("PEP 740 provenance has no attestation_bundles[0].attestations[0].envelope")
    statement = envelope.get("statement")
    signature = envelope.get("signature")
    if not isinstance(statement, str) or not isinstance(signature, str):
        raise SystemExit("PEP 740 envelope missing string 'statement' / 'signature' fields")
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": statement,
        "signatures": [{"sig": signature}],
    }


def view_provenance_bundle(bundle_path: Path, *, full: bool = False) -> int:
    if not bundle_path.is_file():
        raise SystemExit(f"Provenance bundle not found: {bundle_path}")
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {bundle_path}: {exc}") from exc

    ui_step(f"Attestation · {bundle_path.name}")
    ui_info(str(bundle_path.resolve()))
    for line in attestation_summary_lines(bundle_path):
        print(f"    {line}")

    statement = extract_attestation_statement(bundle)
    show_full = full
    if not show_full:
        answer = input(dim("  Show full JSON? [y/N]: ")).strip().lower()
        show_full = answer in {"y", "yes"}

    if show_full:
        print()
        print(dim("── raw provenance JSON ──"))
        printed = json.dumps(bundle, indent=2)
        print(printed[:8000])
        if len(printed) > 8000:
            print(dim("\n... truncated; open the file for the rest"))
        if statement is not None:
            print()
            print(dim("── decoded SLSA / in-toto statement ──"))
            stmt = json.dumps(statement, indent=2)
            print(stmt[:12000])
            if len(stmt) > 12000:
                print(dim("\n... truncated"))
    elif statement is None:
        ui_warn("no attestation statement could be decoded")
    return 0


def normalize_python_package_name(name: str) -> str:
    """PEP 503 / Integrity API normalized project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def python_repo_tier(index_url: str) -> str | None:
    path = urllib.parse.urlsplit(index_url).path.lower()
    for tier in ("predisclosure", "remediated", "validated"):
        if f"/{tier}/" in path or path.rstrip("/").endswith(f"/{tier}"):
            return tier
    return None


def parse_wheel_version(package_name: str, wheel_filename: str) -> str | None:
    """Extract version from a wheel filename given the project name."""
    if not wheel_filename.lower().endswith(".whl"):
        return None
    stem = wheel_filename[:-4]
    candidates = {
        package_name.replace("-", "_"),
        package_name.replace("_", "-"),
        normalize_python_package_name(package_name).replace("-", "_"),
    }
    for cand in candidates:
        prefix = cand.lower() + "-"
        if not stem.lower().startswith(prefix):
            continue
        rest = stem[len(cand) + 1 :]
        parts = rest.split("-")
        # version[-build]-python-abi-platform
        if len(parts) < 4:
            continue
        mid = parts[:-3]
        if len(mid) == 1:
            return mid[0]
        # Optional build tag starts with a digit (PEP 427).
        if re.match(r"^\d", mid[-1]):
            return "-".join(mid[:-1])
        return "-".join(mid)
    return None


def python_provenance_url(repository: str, package: str, version: str, wheel: str) -> str:
    pkg = urllib.parse.quote(normalize_python_package_name(package), safe="-")
    ver = urllib.parse.quote(version, safe="+._-")
    whl = urllib.parse.quote(wheel, safe=".+_-")
    return (
        f"https://packages.redhat.com/api/pypi/lightwell/python/{repository}/"
        f"integrity/{pkg}/{ver}/{whl}/provenance/"
    )


def default_bundle_for_wheel(wheel_path: Path) -> Path:
    return wheel_path.with_name(wheel_path.name + PYTHON_PROVENANCE_SUFFIX)


def verify_java_provenance(jar_path: Path, bundle_path: Path) -> int:
    """Cryptographically verify jar ↔ provenance with cosign + PNC key 1."""
    if not jar_path.is_file():
        raise SystemExit(f"Jar not found: {jar_path}")
    if not bundle_path.is_file():
        raise SystemExit(
            f"Provenance bundle not found: {bundle_path}\n"
            f"Expected sibling file, or pass --bundle PATH."
        )

    cosign = shutil.which("cosign")
    if not cosign:
        raise SystemExit(
            "cosign is required to verify provenance.\n"
            "Install: https://docs.sigstore.dev/cosign/system_config/installation/\n"
            "You can still view the bundle with:\n"
            f"  python3 {Path(__file__).name} --view-provenance {bundle_path}"
        )

    ui_step("Verify Java attestation (cosign)")
    ui_info(f"jar: {jar_path.name}")
    ui_info(f"bundle: {bundle_path.name}")
    ui_info("key: PNC Provenance Signing Key 1")

    with tempfile.TemporaryDirectory(prefix="lightwell-pnc-") as tmp:
        key_path = Path(tmp) / "pnc-provenance-signing-key-1.pub"
        key_path.write_text(PNC_PROVENANCE_SIGNING_KEY_1, encoding="utf-8")
        cmd = [
            cosign,
            "verify-blob-attestation",
            "--type",
            SLSA_PROVENANCE_TYPE,
            "--key",
            str(key_path),
            "--bundle",
            str(bundle_path),
            str(jar_path),
        ]
        ui_info("running cosign verify-blob-attestation …")
        result = subprocess.run(cmd, check=False)
        if result.returncode == 0:
            ui_ok("verification passed — signature and subject digest match")
        else:
            ui_err(f"verification failed (exit {result.returncode})")
        return result.returncode


def handle_java_provenance(
    artifact_name: str,
    artifact_url: str,
    jar_dest: Path,
    user: str,
    token: str,
    output_dir: Path,
) -> Path | None:
    """After downloading a main jar, fetch its provenance; skip classifier jars."""
    if not artifact_name.lower().endswith(".jar"):
        return None

    if is_classifier_jar(artifact_name):
        main_jar_name = jar_stem_without_classifier(artifact_name[: -len(".jar")]) + ".jar"
        ui_warn(
            f"attestation is only published for the main jar ({main_jar_name}), "
            f"not classifier jars like {artifact_name}"
        )
        ui_info("skipping provenance download — get the main jar to fetch/verify attestation")
        return None

    prov_name = provenance_name_for_jar(artifact_name)
    prov_url = provenance_url_for_jar(artifact_url)
    if not prov_name or not prov_url:
        return None

    local_bundle = output_dir / prov_name
    if local_bundle.is_file():
        ui_ok(f"attestation already present: {local_bundle.name}")
    else:
        ui_step("Fetch attestation (main jar)")
        downloaded = download_file(prov_url, user, token, output_dir, optional=True)
        if downloaded is None:
            ui_warn("no provenance published for this main artifact on this tier")
            return None
        local_bundle = downloaded

    action = input(
        dim("  Attestation next: [v]iew  [c]heck/verify  [b]oth  [s]kip [s]: ")
    ).strip().lower()
    if action in {"", "s", "skip", "n", "no"}:
        return local_bundle
    if action in {"v", "view", "b", "both"}:
        view_provenance_bundle(local_bundle)
    if action in {"c", "check", "verify", "b", "both"}:
        verify_java_provenance(jar_dest, local_bundle)
    return local_bundle


def verify_python_provenance(wheel_path: Path, provenance_path: Path) -> int:
    """Verify wheel ↔ PEP 740 provenance with cosign + RELEASE3 (per Lightwell docs)."""
    if not wheel_path.is_file():
        raise SystemExit(f"Wheel not found: {wheel_path}")
    if not provenance_path.is_file():
        raise SystemExit(
            f"Provenance file not found: {provenance_path}\n"
            f"Expected sibling <wheel>.provenance.json, or pass --bundle PATH."
        )

    cosign = shutil.which("cosign")
    if not cosign:
        raise SystemExit(
            "cosign is required to verify provenance.\n"
            "Install: https://docs.sigstore.dev/cosign/system_config/installation/\n"
            "You can still view the file with:\n"
            f"  python3 {Path(__file__).name} --view-provenance {provenance_path}"
        )

    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {provenance_path}: {exc}") from exc

    dsse = pep740_to_dsse(provenance)
    ui_step("Verify Python attestation (cosign)")
    ui_info(f"wheel: {wheel_path.name}")
    ui_info(f"provenance: {provenance_path.name}")
    ui_info("key: Red Hat RELEASE3")

    with tempfile.TemporaryDirectory(prefix="lightwell-py-") as tmp:
        key_path = Path(tmp) / "release3.pub"
        dsse_path = Path(tmp) / f"{wheel_path.name}.dsse.json"
        key_path.write_text(RELEASE3_PUBLIC_KEY, encoding="utf-8")
        dsse_path.write_text(json.dumps(dsse), encoding="utf-8")
        cmd = [
            cosign,
            "verify-blob-attestation",
            "--insecure-ignore-tlog",
            "--type",
            SLSA_PROVENANCE_TYPE,
            "--key",
            str(key_path),
            "--signature",
            str(dsse_path),
            str(wheel_path),
        ]
        ui_info("running cosign verify-blob-attestation …")
        result = subprocess.run(cmd, check=False)
        if result.returncode == 0:
            ui_ok("verification passed — signature and subject digest match")
        else:
            ui_err(f"verification failed (exit {result.returncode})")
        return result.returncode


def handle_python_provenance(
    package_name: str,
    artifact_name: str,
    index_url: str,
    wheel_dest: Path,
    user: str,
    token: str,
    output_dir: Path,
) -> Path | None:
    """After downloading a wheel, always try to fetch PEP 740 provenance; then offer view/verify."""
    if not artifact_name.lower().endswith(".whl"):
        ui_info("Python attestation auto-fetch applies to wheels (.whl) only — skipping")
        return None

    repository = python_repo_tier(index_url)
    version = parse_wheel_version(package_name, artifact_name)
    if not repository:
        ui_warn("could not determine repo tier from index URL — skipping provenance")
        return None
    if not version:
        ui_warn(f"could not parse version from '{artifact_name}' — skipping provenance")
        return None

    prov_name = artifact_name + PYTHON_PROVENANCE_SUFFIX
    prov_url = python_provenance_url(repository, package_name, version, artifact_name)
    local_prov = output_dir / prov_name

    if local_prov.is_file():
        ui_ok(f"attestation already present: {local_prov.name}")
    else:
        ui_step("Fetch attestation (Python Integrity API)")
        ui_info(
            f"{normalize_python_package_name(package_name)} @ {version} · {repository}"
        )
        downloaded = download_file(
            prov_url, user, token, output_dir, optional=True, filename=prov_name
        )
        if downloaded is None:
            ui_warn("no provenance published for this wheel (or Integrity API path mismatch)")
            return None
        local_prov = downloaded

    action = input(
        dim("  Attestation next: [v]iew  [c]heck/verify  [b]oth  [s]kip [s]: ")
    ).strip().lower()
    if action in {"", "s", "skip", "n", "no"}:
        return local_prov
    if action in {"v", "view", "b", "both"}:
        view_provenance_bundle(local_prov)
    if action in {"c", "check", "verify", "b", "both"}:
        verify_python_provenance(wheel_dest, local_prov)
    return local_prov


def resolve_credentials(user: str | None, token: str | None) -> tuple[str, str]:
    # Prefer CLI flags, then shell env (LW_USER / LW_TOKEN), then prompt.
    if not user:
        user = os.environ.get("LW_USER")
        if user:
            ui_info("username from $LW_USER")
    if not token:
        token = os.environ.get("LW_TOKEN")
        if token:
            ui_info("token from $LW_TOKEN")

    if not user:
        user = input(dim("  Username (XXXXXXX|name): ")).strip()
    if not token:
        token = getpass.getpass("  Token: ")
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
        ui_warn(f"username usually looks like '12345678|my-sa-name' — got {user!r}")
    return user, token


def guess_kind(url: str) -> str:
    path = urllib.parse.urlsplit(url).path.lower()
    if "/python/" in path or path.rstrip("/").endswith("/simple") or "/simple/" in path:
        return "python"
    if "/javascript/" in path or "/npm/" in path:
        return "javascript"
    if "/java/" in path:
        return "java"
    # Custom override: prefer python simple-index semantics if unsure.
    return "python"


def npm_package_metadata_url(registry_url: str, package_name: str) -> str:
    """Build npm registry metadata URL (scoped names use %2F)."""
    base = ensure_trailing_slash(registry_url)
    # npm expects /@scope%2Fname — encode slash but keep leading @.
    encoded = urllib.parse.quote(package_name, safe="@")
    return urllib.parse.urljoin(base, encoded)


def list_npm_packages_via_search(
    registry_url: str, user: str, token: str, name_filter: str
) -> list[tuple[str, str]]:
    """Try npm search API; return [(name, metadata_url), ...]."""
    base = ensure_trailing_slash(registry_url)
    query = urllib.parse.urlencode(
        {
            "text": name_filter or "*",
            "size": "250",
        }
    )
    search_url = urllib.parse.urljoin(base, f"-/v1/search?{query}")
    try:
        data = fetch_json(search_url, user, token)
    except SystemExit as exc:
        # Non-auth failures: treat as unsupported search endpoint.
        msg = str(exc)
        if msg.startswith("HTTP 401") or msg.startswith("HTTP 403"):
            raise
        return []

    if not isinstance(data, dict):
        return []
    objects = data.get("objects")
    if not isinstance(objects, list):
        return []

    packages: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in objects:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package")
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        if not isinstance(name, str) or not name or name in seen:
            continue
        seen.add(name)
        packages.append((name, npm_package_metadata_url(base, name)))
    packages.sort(key=lambda item: item[0].lower())
    return packages


def list_npm_packages_via_html(
    registry_url: str, user: str, token: str, name_filter: str
) -> list[tuple[str, str]]:
    """Fallback: parse HTML directory listing if the registry serves one."""
    html = fetch_html(registry_url, user, token)
    packages: list[tuple[str, str]] = []
    for name, url in extract_links(html, registry_url):
        lower = name.lower()
        if lower.endswith((".tgz", ".json", ".html")):
            continue
        packages.append((name, npm_package_metadata_url(registry_url, name)))
    packages.sort(key=lambda item: item[0].lower())
    if name_filter:
        needle = name_filter.lower()
        packages = [(n, u) for n, u in packages if needle in n.lower()]
    return packages


def list_npm_packages(
    registry_url: str, user: str, token: str, name_filter: str
) -> list[tuple[str, str]]:
    packages = list_npm_packages_via_search(registry_url, user, token, name_filter)
    if packages:
        return packages
    print("npm search API unavailable; trying HTML listing...")
    return list_npm_packages_via_html(registry_url, user, token, name_filter)


def list_npm_versions(package_url: str, user: str, token: str) -> list[tuple[str, str]]:
    """Return [(version_label, tarball_url), ...] from package metadata JSON."""
    data = fetch_json(package_url, user, token)
    if not isinstance(data, dict):
        raise SystemExit(f"Unexpected package metadata at {package_url}")

    versions = data.get("versions")
    if not isinstance(versions, dict) or not versions:
        raise SystemExit(f"No versions in package metadata at {package_url}")

    dist_tags = data.get("dist-tags") if isinstance(data.get("dist-tags"), dict) else {}
    latest = dist_tags.get("latest") if isinstance(dist_tags, dict) else None

    artifacts: list[tuple[str, str]] = []
    for version, meta in versions.items():
        if not isinstance(meta, dict):
            continue
        dist = meta.get("dist")
        if not isinstance(dist, dict):
            continue
        tarball = dist.get("tarball")
        if not isinstance(tarball, str) or not tarball:
            continue
        label = f"{version} (latest)" if version == latest else str(version)
        artifacts.append((label, tarball))

    # Newest-looking first by loose string sort of version key descending is weak;
    # keep ascending for stable browsing, with latest tagged in the label.
    artifacts.sort(key=lambda item: item[0].lower())
    return artifacts


def prompt_package_name(name_filter: str = "") -> str:
    hint = f" [{name_filter}]" if name_filter else ""
    while True:
        raw = input(f"Enter npm package name{hint} (or q to quit): ").strip()
        if not raw and name_filter:
            return name_filter
        if not raw:
            continue
        if raw.lower() in {"q", "quit", "exit"}:
            raise SystemExit("Cancelled.")
        return raw


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
    ui_step("Load package list")
    packages = list_python_packages(index_url, user, token, name_filter)
    if not packages:
        raise SystemExit("No packages found (check credentials, entitlement, or --filter).")
    ui_ok(f"{len(packages)} packages")

    package_name, package_url = prompt_choice(
        f"Packages ({len(packages)}) — pick one",
        packages,
        allow_filter=True,
    )
    ui_ok(f"selected {package_name}")

    ui_step("Load artifacts")
    artifacts = list_python_artifacts(package_url, user, token)
    if not artifacts:
        raise SystemExit(f"No downloadable artifacts (.whl/.tar.gz/...) under {package_url}")
    ui_ok(f"{len(artifacts)} artifacts")

    artifact_name, artifact_url = prompt_choice(
        f"Artifacts for '{package_name}' ({len(artifacts)}) — pick one",
        artifacts,
        allow_filter=True,
    )

    confirm = input(dim(f"  Download {bold(artifact_name)}? [Y/n]: ")).strip().lower()
    if confirm in {"n", "no"}:
        print(yellow("Cancelled."))
        return 0

    ui_step("Download")
    dest = download_file(artifact_url, user, token, output_dir)
    if dest is None:
        raise SystemExit("Download failed.")
    attest = handle_python_provenance(
        package_name, artifact_name, index_url, dest, user, token, output_dir
    )
    print_download_summary(artifact=dest, attestation=attest)
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
        path_hint = urllib.parse.urlsplit(current).path.rstrip("/") or "/"
        ui_step(f"Browse {dim(path_hint)}")
        directories, artifacts, provenance = list_java_entries(current, user, token)

        options: list[tuple[str, str]] = []
        parent = parent_url(current, root_url)
        if parent is not None:
            options.append(("../ (up one level)", parent))
        for name, url in directories:
            options.append((f"[dir]   {name}", url))
        for name, url in artifacts:
            options.append((f"[file]  {name}", url))
        for name, url in provenance:
            options.append((f"[attest] {name}", url))

        if not options:
            raise SystemExit(
                f"No browsable entries under {current}\n"
                "(Maven roots may not list everything; try a known group path via --index-url.)"
            )

        label, chosen_url = prompt_choice(
            f"{len(directories)} dirs · {len(artifacts)} files · {len(provenance)} attestations",
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

        if label.startswith("[attest]"):
            artifact_name = label.removeprefix("[attest]").strip()
        else:
            artifact_name = label.removeprefix("[file]").strip()

        confirm = input(dim(f"  Download {bold(artifact_name)}? [Y/n]: ")).strip().lower()
        if confirm in {"n", "no"}:
            ui_info("skipped — still browsing")
            continue

        ui_step("Download")
        dest = download_file(chosen_url, user, token, output_dir)
        if dest is None:
            continue

        notes: list[str] = []
        if is_provenance_bundle(artifact_name):
            view = input(dim("  View this attestation? [Y/n]: ")).strip().lower()
            if view not in {"n", "no"}:
                view_provenance_bundle(dest)
            jar_guess = dest.with_name(dest.name[: -len(PROVENANCE_SUFFIX)] + ".jar")
            if jar_guess.is_file():
                check = input(
                    dim(f"  Verify against {jar_guess.name} with cosign? [y/N]: ")
                ).strip().lower()
                if check in {"y", "yes"}:
                    verify_java_provenance(jar_guess, dest)
            print_download_summary(attestation=dest)
        else:
            attest = handle_java_provenance(
                artifact_name, chosen_url, dest, user, token, output_dir
            )
            if is_classifier_jar(artifact_name):
                notes.append("classifier jar — attestation only exists for the main jar")
            print_download_summary(artifact=dest, attestation=attest, notes=notes)

        again = input(dim("  Download another from this repo? [y/N]: ")).strip().lower()
        if again in {"y", "yes"}:
            continue
        return 0


def run_javascript_flow(
    registry_url: str, user: str, token: str, output_dir: Path, name_filter: str
) -> int:
    """Browse npm registry: list/search packages → versions → download tarball."""
    ui_step("Load npm packages")
    packages = list_npm_packages(registry_url, user, token, name_filter)
    if not packages:
        ui_warn("could not list packages automatically — enter a name")
        package_name = prompt_package_name(name_filter)
        package_url = npm_package_metadata_url(registry_url, package_name)
    else:
        ui_ok(f"{len(packages)} packages")
        package_name, package_url = prompt_choice(
            f"Packages ({len(packages)}) — pick one",
            packages,
            allow_filter=True,
        )

    ui_ok(f"selected {package_name}")
    ui_step("Load versions")
    artifacts = list_npm_versions(package_url, user, token)
    if not artifacts:
        raise SystemExit(f"No downloadable tarballs under {package_url}")
    ui_ok(f"{len(artifacts)} versions")

    version_label, tarball_url = prompt_choice(
        f"Versions for '{package_name}' ({len(artifacts)}) — pick one",
        artifacts,
        allow_filter=True,
    )

    confirm = input(
        dim(f"  Download {bold(f'{package_name}@{version_label}')}? [Y/n]: ")
    ).strip().lower()
    if confirm in {"n", "no"}:
        print(yellow("Cancelled."))
        return 0

    ui_step("Download")
    dest = download_file(tarball_url, user, token, output_dir)
    if dest is None:
        raise SystemExit("Download failed.")
    print_download_summary(artifact=dest)
    return 0


def _name_matches_filter(name: str, name_filter: str) -> bool:
    if not name_filter:
        return True
    return name_filter.lower() in name.lower()


def _java_matches_filter(name: str, url: str, name_filter: str) -> bool:
    """Match filter against artifact name or full Maven URL path (e.g. …/awssdk/…)."""
    if not name_filter:
        return True
    needle = name_filter.lower().replace(".", "/")
    hay_name = name.lower()
    hay_url = urllib.parse.unquote(url).lower()
    return (
        name_filter.lower() in hay_name
        or name_filter.lower() in hay_url
        or needle in hay_url
    )


def _java_estimate_seed_urls(root_url: str, name_filter: str) -> list[str]:
    """Prefer jumping into a Maven group/artifact path when the filter looks like one."""
    root = ensure_trailing_slash(root_url)
    seeds: list[str] = []
    raw = (name_filter or "").strip().strip("/")
    if raw:
        # software.amazon.awssdk  or  software/amazon/awssdk
        path = raw.replace(".", "/") if "/" not in raw and " " not in raw else raw
        # Bare tokens like "awssdk" are not full paths — don't invent a root child.
        if "/" in path or "." in raw:
            seeds.append(urllib.parse.urljoin(root, path.strip("/") + "/"))
    seeds.append(root)
    # Dedupe, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for url in seeds:
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def collect_python_estimate_targets(
    index_url: str, user: str, token: str, name_filter: str, max_artifacts: int
) -> list[tuple[str, str]]:
    """Return up to max_artifacts (name, url) wheel/sdist targets."""
    packages = list_python_packages(index_url, user, token, name_filter)
    targets: list[tuple[str, str]] = []
    for package_name, package_url in packages:
        if len(targets) >= max_artifacts:
            break
        try:
            artifacts = list_python_artifacts(package_url, user, token)
        except SystemExit:
            continue
        for name, url in artifacts:
            targets.append((f"{package_name}/{name}", url))
            if len(targets) >= max_artifacts:
                break
    return targets


def _java_dir_sort_key(name: str, url: str, needle: str) -> tuple:
    """Lower sort key = explore sooner (filter hits and common Maven roots first)."""
    n = name.rstrip("/").lower()
    u = urllib.parse.unquote(url).lower()
    common_roots = {
        "software",
        "com",
        "org",
        "io",
        "net",
        "jakarta",
        "javax",
        "redis",
        "cn",
        "edu",
    }
    if needle:
        needle_path = needle.replace(".", "/")
        if n == needle or n == needle_path.rsplit("/", 1)[-1]:
            return (0, n)
        if needle in n or needle in u or needle_path in u:
            return (1, n)
    if n in common_roots:
        return (2, n)
    return (3, n)


def collect_java_estimate_targets(
    root_url: str, user: str, token: str, name_filter: str, max_artifacts: int
) -> list[tuple[str, str]]:
    """Walk Maven directories; collect artifact URLs until max_artifacts."""
    targets: list[tuple[str, str]] = []
    queue: deque[str] = deque(_java_estimate_seed_urls(root_url, name_filter))
    seen_dirs: set[str] = set()
    # Deep Maven trees need many directory visits before the first matching jar.
    max_dirs = max(2000, max_artifacts * 50)
    needle = (name_filter or "").lower()

    ui_info(f"java walk cap {max_dirs} directories (artifact cap {max_artifacts})")
    if needle and "/" not in needle and "." not in needle:
        ui_info(
            "tip: path filters find Maven groupIds faster, e.g. "
            "--filter software/amazon/awssdk"
        )

    while queue and len(targets) < max_artifacts and len(seen_dirs) < max_dirs:
        current = queue.popleft()
        if current in seen_dirs:
            continue
        seen_dirs.add(current)
        if len(seen_dirs) == 1 or len(seen_dirs) % 25 == 0:
            path_hint = urllib.parse.urlsplit(current).path
            ui_info(f"listed {len(seen_dirs)} dirs · queued {len(queue)} · at {path_hint}")

        try:
            directories, artifacts, _provenance = list_java_entries(current, user, token)
        except SystemExit as exc:
            msg = str(exc)
            if "HTTP 401" in msg or "HTTP 403" in msg:
                raise
            # Seeded group paths may 404 if the filter isn't an exact path prefix.
            if "HTTP 404" in msg and current != ensure_trailing_slash(root_url):
                ui_warn(f"path not found, continuing from repo root: {current}")
                continue
            ui_warn(f"skip listing {current}: {exc}")
            continue

        for name, url in artifacts:
            if not is_estimate_binary(name):
                continue
            if not _java_matches_filter(name, url, name_filter):
                continue
            targets.append((name, url))
            if len(targets) >= max_artifacts:
                break

        children = [(name, url) for name, url in directories if url not in seen_dirs]
        children.sort(key=lambda item: _java_dir_sort_key(item[0], item[1], needle))
        # Explore best matches first (appendleft in reverse so first key is next).
        for _name, url in reversed(children):
            queue.appendleft(url)

    if not targets and seen_dirs:
        ui_warn(
            f"walked {len(seen_dirs)} directories without matching artifacts "
            f"(filter={name_filter!r}). Try a path-like filter, e.g. "
            f"--filter software/amazon/awssdk or --filter software.amazon.awssdk"
        )
    return targets


def collect_javascript_estimate_targets(
    registry_url: str, user: str, token: str, name_filter: str, max_artifacts: int
) -> list[tuple[str, str]]:
    packages = list_npm_packages(registry_url, user, token, name_filter)
    targets: list[tuple[str, str]] = []
    for package_name, package_url in packages:
        if len(targets) >= max_artifacts:
            break
        try:
            versions = list_npm_versions(package_url, user, token)
        except SystemExit:
            continue
        for label, tarball_url in versions:
            targets.append((f"{package_name}@{label}", tarball_url))
            if len(targets) >= max_artifacts:
                break
    return targets


def run_estimate_size(
    *,
    label: str,
    kind: str,
    index_url: str,
    user: str,
    token: str,
    name_filter: str,
    max_artifacts: int,
) -> int:
    if max_artifacts < 1:
        raise SystemExit("--max-artifacts must be >= 1")

    ui_step("Size estimate (HEAD only)")
    ui_ok(f"repo {label}")
    ui_info(index_url)
    if name_filter:
        ui_info(f"filter '{name_filter}'")
    ui_info(f"cap {max_artifacts} artifacts")
    ui_warn("sample estimate — not a full catalog mirror size")

    if kind == "python":
        targets = collect_python_estimate_targets(
            index_url, user, token, name_filter, max_artifacts
        )
    elif kind == "javascript":
        targets = collect_javascript_estimate_targets(
            index_url, user, token, name_filter, max_artifacts
        )
    else:
        targets = collect_java_estimate_targets(
            index_url, user, token, name_filter, max_artifacts
        )

    if not targets:
        ui_warn("no artifacts found to measure (check --repo / --filter)")
        return 1

    ui_step(f"Probe size for {len(targets)} artifacts")
    measured = 0
    unknown = 0
    total_bytes = 0
    largest: list[tuple[int, str]] = []

    for i, (name, url) in enumerate(targets, start=1):
        print(f"  {dim(f'{i:>3}')}  {name}  {dim('…')}", end="", flush=True)
        try:
            size = head_content_length(url, user, token)
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001 — never abort the whole estimate on one probe
            size = None
            print(f"\r  {dim(f'{i:>3}')}  {name}  {yellow('?')}  {dim(str(exc)[:60])}")
            unknown += 1
            continue
        if size is None:
            unknown += 1
            print(f"\r  {dim(f'{i:>3}')}  {name}  {yellow('? (timeout/no length)')}")
        else:
            measured += 1
            total_bytes += size
            largest.append((size, name))
            print(f"\r  {dim(f'{i:>3}')}  {name}  {green(human_size(size))}")

    largest.sort(reverse=True)

    print()
    print(bold("── Size estimate ──"))
    ui_ok(f"measured {measured}/{len(targets)} artifacts → {human_size(total_bytes)}")
    if unknown:
        ui_warn(f"{unknown} without Content-Length")
    if measured:
        avg = total_bytes // measured
        ui_info(f"average measured artifact ≈ {human_size(avg)}")
        if len(targets) >= max_artifacts:
            ui_info(
                f"hit --max-artifacts={max_artifacts}; "
                f"naive extrapolation if density is similar ≈ "
                f"{human_size(avg * max_artifacts)} for this sample window only"
            )
            ui_warn("do not multiply to 'whole catalog' — trees are uneven")
    if largest:
        print(dim("  largest in sample:"))
        for size, name in largest[:5]:
            print(f"    {human_size(size):>10}  {name}")
    print()
    return 0


def main() -> int:
    args = parse_args()
    ui_banner()

    # Offline provenance helpers (no registry auth required).
    if args.view_provenance:
        return view_provenance_bundle(Path(args.view_provenance).expanduser())
    if args.verify_java and args.verify_python:
        raise SystemExit("Use only one of --verify-java or --verify-python.")
    if args.verify_java:
        jar_path = Path(args.verify_java).expanduser()
        bundle_path = (
            Path(args.bundle).expanduser()
            if args.bundle
            else default_bundle_for_jar(jar_path)
        )
        if bundle_path.is_file():
            view_provenance_bundle(bundle_path)
            print_download_summary(artifact=jar_path, attestation=bundle_path)
        return verify_java_provenance(jar_path, bundle_path)
    if args.verify_python:
        wheel_path = Path(args.verify_python).expanduser()
        bundle_path = (
            Path(args.bundle).expanduser()
            if args.bundle
            else default_bundle_for_wheel(wheel_path)
        )
        if bundle_path.is_file():
            view_provenance_bundle(bundle_path)
            print_download_summary(artifact=wheel_path, attestation=bundle_path)
        return verify_python_provenance(wheel_path, bundle_path)

    user, token = resolve_credentials(args.user, args.token)
    label, kind, index_url = select_repo(args)

    if args.estimate_size:
        return run_estimate_size(
            label=label,
            kind=kind,
            index_url=index_url,
            user=user,
            token=token,
            name_filter=args.filter,
            max_artifacts=args.max_artifacts,
        )

    output_dir = Path(args.output_dir).expanduser()
    ui_step("Session")
    ui_ok(f"repo {label}")
    ui_info(index_url)
    ui_info(f"user {user}")
    ui_info(f"output {output_dir.resolve()}")

    if kind == "python":
        return run_python_flow(index_url, user, token, output_dir, args.filter)
    if kind == "javascript":
        return run_javascript_flow(index_url, user, token, output_dir, args.filter)
    return run_java_flow(index_url, user, token, output_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print(yellow("Cancelled."))
        raise SystemExit(130)

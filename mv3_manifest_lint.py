#!/usr/bin/env python3
"""mv3-manifest-lint -- a static linter for Chrome Manifest V3 extensions.

Reads ``manifest.json`` (plus the files it references) and reports the mistakes
that get an extension rejected from the Chrome Web Store, or that leave it
broken at runtime once it is packaged.

Nothing here talks to Chrome, the network, or the file system outside the
extension directory being linted.  Standard library only.

Exit codes
----------
0   no findings at or above the requested severity threshold
1   at least one finding at or above the threshold
2   usage error, unreadable path, or malformed manifest JSON

Severities
----------
high    breaks the extension at runtime, or is a hard Chrome manifest /
        package error.  Also used for remotely hosted code, which is a
        declared MV3 policy violation.
medium  not fatal, but will very likely cost a store rejection or a broken
        experience (missing 128px icon, over-long description, ...).
low     informational / review-risk.  Flagged for a human to look at.

Where a rule is a Chrome Web Store *review* convention rather than a hard
runtime or manifest-validation rule, the finding carries ``review: true`` and
the rendered text says so explicitly.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Iterable, Mapping, Sequence

__version__ = "1.0.0"

TOOL_NAME = "mv3-manifest-lint"
MANIFEST_FILENAME = "manifest.json"

# --------------------------------------------------------------------------
# Severities
# --------------------------------------------------------------------------

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

SEVERITY_RANK = {LOW: 1, MEDIUM: 2, HIGH: 3}
SEVERITY_CHOICES = (HIGH, MEDIUM, LOW)
SEVERITY_ALIASES = {
    "h": HIGH,
    "hi": HIGH,
    "high": HIGH,
    "m": MEDIUM,
    "med": MEDIUM,
    "medium": MEDIUM,
    "l": LOW,
    "lo": LOW,
    "low": LOW,
    "all": LOW,
}


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One problem found in an extension."""

    rule: str
    severity: str
    title: str
    message: str
    fix: str
    file: str = MANIFEST_FILENAME
    line: int | None = None
    review: bool = False
    context: Mapping[str, Any] | None = None

    @property
    def location(self) -> str:
        if self.line is not None:
            return f"{self.file}:{self.line}"
        return self.file

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "fix": self.fix,
            "file": self.file,
            "line": self.line,
            "review": self.review,
        }
        if self.context:
            out["context"] = dict(self.context)
        return out

    def sort_key(self) -> tuple[int, str, int, str]:
        return (
            -SEVERITY_RANK[self.severity],
            self.file,
            self.line if self.line is not None else -1,
            self.rule,
        )


class FindingCollector:
    """Accumulates findings for one run.

    Two identical findings are recorded once.  ``dedupe`` lets a caller key
    that decision on something narrower than the whole message -- the
    missing-file rule uses the path, so a file named by three different
    manifest keys produces one finding rather than three.
    """

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._seen: set[Any] = set()

    def add(
        self,
        rule: str,
        severity: str,
        title: str,
        message: str,
        fix: str,
        *,
        file: str = MANIFEST_FILENAME,
        line: int | None = None,
        review: bool = False,
        context: Mapping[str, Any] | None = None,
        dedupe: Any = None,
    ) -> Finding:
        key = (
            rule,
            file,
            line,
            ("msg", message) if dedupe is None else ("key", dedupe),
        )
        if key in self._seen:
            return Finding(
                rule=rule,
                severity=severity,
                title=title,
                message=message,
                fix=fix,
                file=file,
                line=line,
                review=review,
                context=dict(context) if context else None,
            )
        self._seen.add(key)
        finding = Finding(
            rule=rule,
            severity=severity,
            title=title,
            message=message,
            fix=fix,
            file=file,
            line=line,
            review=review,
            context=dict(context) if context else None,
        )
        self._findings.append(finding)
        return finding

    def __len__(self) -> int:
        return len(self._findings)

    def __iter__(self):
        return iter(self._findings)

    def sorted(self) -> list[Finding]:
        return sorted(self._findings, key=Finding.sort_key)

    def counts(self) -> dict[str, int]:
        out = {HIGH: 0, MEDIUM: 0, LOW: 0}
        for finding in self._findings:
            out[finding.severity] += 1
        return out


# --------------------------------------------------------------------------
# Rule registry
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    title: str
    description: str
    review: bool = False


RULES: tuple[Rule, ...] = (
    Rule(
        "META-004",
        HIGH,
        "missing manifest_version",
        "manifest_version is required. A manifest without it is treated as "
        "Manifest V2.",
    ),
    Rule(
        "MV2-001",
        HIGH,
        "manifest_version is 2",
        "Chrome no longer accepts Manifest V2 extensions, so this manifest "
        "cannot be loaded or published. This is a deliberate, dated decision "
        "by Chrome rather than something this tool can schedule.",
    ),
    Rule(
        "META-001",
        HIGH,
        "missing 'description'",
        "description is required by the manifest schema and is also the text "
        "shown on the store listing.",
    ),
    Rule(
        "META-002",
        MEDIUM,
        "description longer than 132 characters",
        "The Chrome Web Store listing description field is capped at 132 "
        "characters, so a longer value is refused at upload time.",
    ),
    Rule(
        "META-003",
        HIGH,
        "missing or malformed 'version'",
        "version is required and must be 1 to 4 dot-separated integers, each "
        "0-65535. So '1.2.3' is fine and '1.2.3-beta' or 'v1.2' is not.",
    ),
    Rule(
        "BG-001",
        HIGH,
        "background.scripts instead of service_worker",
        "Manifest V3 replaces the background page with a single service "
        "worker. A background.scripts array is ignored by Chrome, so none of "
        "the listed code runs.",
    ),
    Rule(
        "BG-002",
        MEDIUM,
        "background.persistent is ignored in MV3",
        "background.persistent only applied to MV2 background pages. A "
        "service worker is always event-driven, so the key has no effect and "
        "its presence means the code was written for MV2.",
    ),
    Rule(
        "BG-003",
        HIGH,
        "background has the wrong shape",
        "background must be an object such as "
        '{"service_worker": "background.js"}.',
    ),
    Rule(
        "CSP-001",
        HIGH,
        "content_security_policy allows remote script",
        "Scripts may only be loaded from inside the extension package. A "
        "script-src (or default-src, which script-src falls back to) that "
        "lists an http(s) origin is remotely hosted code, which MV3 forbids.",
    ),
    Rule(
        "CSP-002",
        HIGH,
        "content_security_policy allows 'unsafe-eval'",
        "Chrome refuses to load an MV3 extension whose script-src contains "
        "'unsafe-eval', because it re-enables eval() and new Function().",
    ),
    Rule(
        "CSP-003",
        HIGH,
        "content_security_policy script-src is not 'self'",
        "MV3 pins script-src to 'self'. Extra sources -- including "
        "https://*/* or a localhost dev server -- are why the extension "
        "fails to load.",
    ),
    Rule(
        "CSP-005",
        MEDIUM,
        "content_security_policy enables 'wasm-unsafe-eval'",
        "Chrome accepts 'wasm-unsafe-eval' in an MV3 script-src; it is "
        "required only for WebAssembly. Flagged so an unnecessary relaxation "
        "does not ship unnoticed.",
    ),
    Rule(
        "CSP-004",
        MEDIUM,
        "content_security_policy is not parseable",
        "content_security_policy must be an object with extension_pages / "
        "sandbox strings, or a plain string. Anything else means the policy "
        "you meant to set is not applied.",
    ),
    Rule(
        "PERM-001",
        HIGH,
        "host pattern in permissions",
        "Match patterns belong in host_permissions. Chrome reads permissions "
        "as a list of API names, so a host pattern there is not a permission "
        "you asked for.",
    ),
    Rule(
        "PERM-002",
        HIGH,
        "API permission in host_permissions",
        "host_permissions accepts match patterns only. An API name such as "
        '"tabs" in that list is silently not granted and the call fails at '
        "runtime.",
    ),
    Rule(
        "PERM-005",
        HIGH,
        "permissions is not an array",
        "permissions must be an array of API name strings.",
    ),
    Rule(
        "PERM-006",
        HIGH,
        "host_permissions is not an array",
        "host_permissions must be an array of match pattern strings.",
    ),
    Rule(
        "WAR-001",
        HIGH,
        "web_accessible_resources uses the MV2 array form",
        "In MV2 web_accessible_resources was a flat array of paths. MV3 "
        "requires an array of objects, each with resources and matches.",
    ),
    Rule(
        "WAR-002",
        HIGH,
        "web_accessible_resources entry missing 'matches'",
        "Every MV3 web_accessible_resources entry needs a non-empty matches "
        "array. Without it the manifest fails to load.",
    ),
    Rule(
        "WAR-003",
        LOW,
        "declarativeNetRequest rule resource may need to be web-accessible",
        "Chrome fetches rule resources named in "
        "declarativeNetRequest.rule_resources through the extension's own "
        "web-accessible resource route, so the ruleset path must also appear "
        "in web_accessible_resources. Reported as a review-risk flag because "
        "this linter cannot load the extension to confirm it.",
    ),
    Rule(
        "WAR-004",
        HIGH,
        "web_accessible_resources is not an array",
        "MV3 requires web_accessible_resources to be an array of objects.",
    ),
    Rule(
        "WAR-005",
        MEDIUM,
        "web_accessible_resources entry has no resources",
        "Each web_accessible_resources entry needs a non-empty resources "
        "array of extension-relative paths.",
    ),
    Rule(
        "ACTION-001",
        HIGH,
        "browser_action / page_action instead of action",
        "MV3 merges the browser action and the page action into a single "
        "action key. Chrome ignores browser_action and page_action, so no "
        "toolbar button appears.",
    ),
    Rule(
        "MATCH-001",
        HIGH,
        "match pattern with no path",
        "A match pattern needs a path component. 'https://example.com' is "
        "not valid; 'https://example.com/*' is. An invalid pattern makes "
        "Chrome refuse the whole manifest.",
    ),
    Rule(
        "MATCH-002",
        LOW,
        "<all_urls> where a narrower pattern would do",
        "Injecting into every origin is the widest request available and "
        "attracts Web Store review scrutiny. Chrome itself allows it: this is "
        "a review-risk flag, not a defect. (Web Store review convention.)",
        review=True,
    ),
    Rule(
        "ICON-001",
        MEDIUM,
        "icons missing the 128px entry",
        "The Chrome Web Store listing needs a 128x128 icon. Chrome itself "
        "can pick an icon without it; the store listing cannot.",
    ),
    Rule(
        "ICON-002",
        MEDIUM,
        "no usable 'icons' key",
        "icons is missing or is not an object keyed by pixel size, so there "
        "is no 128px image for the store listing.",
    ),
    Rule(
        "FILE-001",
        HIGH,
        "referenced file does not exist",
        "The manifest (or a referenced page) points at a file that is not in "
        "the extension directory. This surfaces only after packaging: the "
        "extension loads but the feature is dead, or Chrome refuses the "
        "package.",
    ),
    Rule(
        "FILE-002",
        LOW,
        "referenced path is a glob or directory",
        "The entry is a glob pattern or bare directory rather than a "
        "concrete file, so existence cannot be decided statically.",
    ),
    Rule(
        "CHROME-001",
        LOW,
        "minimum_chrome_version absent for a modern API",
        "The manifest uses an API that only exists from a known Chrome "
        "version, but minimum_chrome_version is not set, so older Chrome "
        "versions will install the extension and fail at runtime.",
    ),
    Rule(
        "REMOTE-001",
        HIGH,
        "importScripts() of a remote URL",
        "The worker pulls executable code over the network. MV3 allows "
        "importScripts only for files inside the extension package.",
    ),
    Rule(
        "REMOTE-002",
        HIGH,
        "dynamic import() of a remote URL",
        "A dynamic import of an http(s) URL fetches executable code at "
        "runtime, which is remotely hosted code and is blocked in MV3.",
    ),
    Rule(
        "REMOTE-003",
        HIGH,
        "eval() or new Function() in extension script",
        "Extension pages run under a CSP without 'unsafe-eval', so eval and "
        "the Function constructor throw at runtime. Their presence also "
        "signals dynamically generated code, which MV3 forbids.",
    ),
    Rule(
        "HTML-001",
        HIGH,
        "extension page loads a remote script",
        "A <script src> pointing at an http(s) URL is remotely hosted code. "
        "It is blocked by the MV3 CSP and is a Web Store policy violation.",
    ),
    Rule(
        "HTML-002",
        HIGH,
        "inline <script> in extension HTML",
        "The MV3 extension_pages CSP has no 'unsafe-inline', so an inline "
        "<script> block does not execute and the page silently loses its "
        "behaviour.",
    ),
    Rule(
        "HTML-003",
        HIGH,
        "inline event handler attribute in extension HTML",
        'Attributes such as onclick="..." are inline script and are blocked '
        "by the MV3 CSP.",
    ),
    Rule(
        "HTML-004",
        LOW,
        "extension page loads a remote stylesheet",
        "A remote <link rel=stylesheet> is not blocked the way a remote "
        "script is (image and style sources are not pinned to 'self'), but it "
        "leaks use of the extension to a third party and breaks offline. "
        "Flagged as a review-risk, not an error.",
        review=True,
    ),
)

RULES_BY_ID: dict[str, Rule] = {rule.rule_id: rule for rule in RULES}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")
_REMOTE_URL_RE = re.compile(r"^(?:https?:)?//", re.IGNORECASE)
_GLOB_RE = re.compile(r"[*?]|\[[^\]]*\]")
_HANDLER_RE = re.compile(r"\bon[a-zA-Z]{2,}\s*=")
# scheme://host/path -- a match pattern with no path component at all is
# invalid, so "https://example.com" is wrong and "https://example.com/*" is
# right.  A trailing "/" is a real (if unusual) path and is accepted.
# Capture groups: 1 = scheme, 2 = host, 3 = optional "*.", 4 = path.
_MATCH_PATTERN_RE = re.compile(
    r"^(\*|https?|file|ftp)://(\*|(\*\.)?[^/*]+)(/.*)?$"
)
_MATCH_PATTERN_PATH_GROUP = 4
_BARE_HOST_RE = re.compile(r"^[A-Za-z0-9*][A-Za-z0-9.\-]*\.[A-Za-z]{2,}(?:/.*)?$")

# APIs whose minimum Chrome version is documented and stable.  Kept short on
# purpose: a wrong version number is worse than no rule at all.
_MIN_CHROME_FOR_PERMISSION: dict[str, tuple[int, str]] = {
    "offscreen": (109, "the offscreen permission"),
    "sidePanel": (114, "the sidePanel permission"),
    "userScripts": (120, "the userScripts permission"),
}

_RE_IMPORT_SCRIPTS = re.compile(
    r"importScripts\s*\(\s*(['\"])(?P<url>[^'\"]+)\1", re.IGNORECASE
)
_RE_DYNAMIC_IMPORT = re.compile(
    r"\bimport\s*\(\s*(['\"])(?P<url>[^'\"]+)\1", re.IGNORECASE
)
_RE_EVAL = re.compile(r"(?<![\w$.])eval\s*\(")
_RE_NEW_FUNCTION = re.compile(r"\bnew\s+Function\s*\(")


def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except (OSError, ValueError):
        return None


def _line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    if count == 1:
        return f"{count} {singular}"
    return f"{count} {plural or singular + 's'}"


def _is_remote_url(value: str) -> bool:
    return bool(_REMOTE_URL_RE.match(value.strip()))


def _relative_url(value: str) -> str:
    out = value.strip()
    while out.startswith("./"):
        out = out[2:]
    return out


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _looks_like_host_pattern(value: str) -> bool:
    """True for anything that belongs in host_permissions, not permissions."""
    text = value.strip()
    if not text:
        return False
    if text == "<all_urls>":
        return True
    if _REMOTE_URL_RE.match(text):
        return True
    if text.startswith("*://") or text.startswith("*."):
        return True
    if text.startswith("/") and len(text) > 1:
        return True
    if _BARE_HOST_RE.match(text):
        return True
    return False


def _looks_like_api_permission(value: str) -> bool:
    """True for a Chrome API permission name (no dots, slashes or schemes)."""
    text = value.strip()
    if not text or text == "<all_urls>":
        return False
    if _looks_like_host_pattern(text):
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", text))


def _is_glob(value: str) -> bool:
    return bool(_GLOB_RE.search(value))


def _unique(items: Iterable[str]) -> list[str]:
    """Order-preserving de-duplication."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _entry_exists(root: str, relpath: str) -> bool:
    return os.path.exists(os.path.normpath(os.path.join(root, relpath)))


# --------------------------------------------------------------------------
# HTML scanning
# --------------------------------------------------------------------------


class _PageParser(HTMLParser):
    """Collects script elements, stylesheet links and inline event handlers."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[tuple[int, dict[str, str]]] = []
        self.links: list[tuple[int, dict[str, str]]] = []
        self.events: list[tuple[int, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        line = self.getpos()[0]
        mapping = {
            name.lower(): (value if value is not None else "") for name, value in attrs
        }
        if tag == "script":
            self.scripts.append((line, mapping))
        elif tag == "link":
            self.links.append((line, mapping))
        for name, value in attrs:
            lowered = name.lower()
            if len(lowered) > 2 and lowered.startswith("on") and lowered.isalpha():
                self.events.append((line, lowered, value or ""))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def _strip_html_comments(text: str) -> str:
    """Blank out <!-- ... -->, preserving line numbers and offsets."""
    out = list(text)
    for match in re.finditer(r"<!--.*?-->", text, re.DOTALL):
        for index in range(match.start(), match.end()):
            if out[index] != "\n":
                out[index] = " "
    return "".join(out)


def _scan_html(root: str, relpath: str, collector: FindingCollector) -> list[str]:
    """Lint one extension HTML page; return the paths it references."""
    path = os.path.normpath(os.path.join(root, relpath))
    text = _read_text(path)
    if text is None:
        return []

    parser = _PageParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # pragma: no cover - HTMLParser is forgiving
        pass

    referenced: list[str] = []

    for line, attrs in parser.scripts:
        src = attrs.get("src", "").strip()
        if not src:
            collector.add(
                "HTML-002",
                HIGH,
                "inline <script> in extension HTML",
                "Inline <script> block. The MV3 extension_pages CSP is "
                "\"script-src 'self'\" with no 'unsafe-inline', so this block "
                "never executes.",
                "Move the code into a .js file in the package and load it "
                'with <script src="..."></script>.',
                file=relpath,
                line=line,
            )
            continue
        if _is_remote_url(src) or _SCHEME_RE.match(src):
            collector.add(
                "HTML-001",
                HIGH,
                "extension page loads a remote script",
                f'<script src="{src}"> loads script from outside the package. '
                "MV3 blocks remotely hosted code, and the store rejects it.",
                "Download the file, commit it inside the extension, and "
                "reference it with a relative path.",
                file=relpath,
                line=line,
                context={"src": src},
            )
            continue
        referenced.append(_relative_url(src))

    for line, attrs in parser.links:
        rel = attrs.get("rel", "").lower()
        href = attrs.get("href", "").strip()
        if "stylesheet" not in rel or not href:
            continue
        if _is_remote_url(href) or _SCHEME_RE.match(href):
            collector.add(
                "HTML-004",
                LOW,
                "extension page loads a remote stylesheet",
                f'<link rel="stylesheet" href="{href}"> pulls CSS from '
                "outside the package. Style sources are not pinned to 'self' "
                "so Chrome allows it, but it tells a third party the "
                "extension is in use and it breaks offline. "
                "(Review convention.)",
                "Vendor the stylesheet into the package.",
                file=relpath,
                line=line,
                review=True,
                context={"href": href},
            )
            continue
        referenced.append(_relative_url(href))

    cleaned = _strip_html_comments(text)
    for match in _HANDLER_RE.finditer(cleaned):
        start = cleaned.rfind("<", 0, match.start())
        if start < 0 or cleaned.find(">", start, match.start()) != -1:
            continue
        name = match.group(0).rstrip("=").strip()
        collector.add(
            "HTML-003",
            HIGH,
            "inline event handler attribute in extension HTML",
            f'{name}="..." is inline script. The MV3 extension_pages CSP has '
            "no 'unsafe-inline', so the handler never runs.",
            "Attach the handler from a script file with addEventListener.",
            file=relpath,
            line=_line_of_offset(cleaned, match.start()),
        )

    return referenced


# --------------------------------------------------------------------------
# JavaScript scanning
# --------------------------------------------------------------------------


def _scan_js(root: str, relpath: str, collector: FindingCollector) -> None:
    """Look for remotely hosted or dynamically evaluated code in a JS file."""
    path = os.path.normpath(os.path.join(root, relpath))
    text = _read_text(path)
    if text is None:
        return

    for match in _RE_IMPORT_SCRIPTS.finditer(text):
        url = match.group("url")
        if not _is_remote_url(url):
            continue
        collector.add(
            "REMOTE-001",
            HIGH,
            "importScripts() of a remote URL",
            f'importScripts("{url}") fetches executable code over the '
            "network. MV3 allows importScripts only for packaged files.",
            "Vendor the script into the package and call "
            "importScripts('lib/vendor.js').",
            file=relpath,
            line=_line_of_offset(text, match.start()),
            context={"url": url},
        )

    for match in _RE_DYNAMIC_IMPORT.finditer(text):
        url = match.group("url")
        if not _is_remote_url(url):
            continue
        collector.add(
            "REMOTE-002",
            HIGH,
            "dynamic import() of a remote URL",
            f'import("{url}") pulls a module off the network at runtime. MV3 '
            "blocks remotely hosted code.",
            "Bundle the module into the package and import a relative path.",
            file=relpath,
            line=_line_of_offset(text, match.start()),
            context={"url": url},
        )

    for match in _RE_EVAL.finditer(text):
        collector.add(
            "REMOTE-003",
            HIGH,
            "eval() or new Function() in extension script",
            "eval() is present. The MV3 extension_pages CSP has no "
            "'unsafe-eval', so this call throws at runtime.",
            "Replace eval with JSON.parse for data, a dispatch table for "
            "code paths and a real template for strings.",
            file=relpath,
            line=_line_of_offset(text, match.start()),
            context={"construct": "eval"},
        )

    for match in _RE_NEW_FUNCTION.finditer(text):
        collector.add(
            "REMOTE-003",
            HIGH,
            "eval() or new Function() in extension script",
            "new Function() compiles a string into code and is blocked by the "
            "MV3 extension_pages CSP (no 'unsafe-eval').",
            "Replace new Function with an explicit function or a lookup "
            "table.",
            file=relpath,
            line=_line_of_offset(text, match.start()),
            context={"construct": "new Function"},
        )


# --------------------------------------------------------------------------
# Manifest traversal
# --------------------------------------------------------------------------


def _collect_icons(value: Any, out: list[tuple[str, str]], origin: str) -> None:
    if isinstance(value, dict):
        for key, target in value.items():
            if isinstance(target, str) and target.strip():
                out.append((_relative_url(target), f"{origin}[{key}]"))
    elif isinstance(value, str) and value.strip():
        out.append((_relative_url(value), origin))


def _collect_referenced_files(manifest: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Return (relpath, manifest-key-that-names-it) pairs."""
    out: list[tuple[str, str]] = []

    def add(value: Any, origin: str) -> None:
        if isinstance(value, str) and value.strip():
            out.append((_relative_url(value), origin))

    background = manifest.get("background")
    if isinstance(background, dict):
        add(background.get("service_worker"), "background.service_worker")
        for item in _as_list(background.get("scripts")):
            add(item, "background.scripts")

    action = manifest.get("action")
    if isinstance(action, dict):
        add(action.get("default_popup"), "action.default_popup")
        _collect_icons(action.get("default_icon"), out, "action.default_icon")

    for key in ("browser_action", "page_action"):
        legacy = manifest.get(key)
        if isinstance(legacy, dict):
            add(legacy.get("default_popup"), f"{key}.default_popup")
            _collect_icons(legacy.get("default_icon"), out, f"{key}.default_icon")

    _collect_icons(manifest.get("icons"), out, "icons")

    for index, entry in enumerate(_as_list(manifest.get("content_scripts"))):
        if not isinstance(entry, dict):
            continue
        for item in _as_list(entry.get("js")):
            add(item, f"content_scripts[{index}].js")
        for item in _as_list(entry.get("css")):
            add(item, f"content_scripts[{index}].css")

    for index, entry in enumerate(_as_list(manifest.get("web_accessible_resources"))):
        if isinstance(entry, dict):
            for item in _as_list(entry.get("resources")):
                add(item, f"web_accessible_resources[{index}].resources")
        elif isinstance(entry, str):
            add(entry, "web_accessible_resources")

    for key, value in manifest.items():
        if key in ("background", "action", "content_scripts",
                   "web_accessible_resources", "icons"):
            continue
        if isinstance(value, dict):
            for inner in ("page", "default_path", "path"):
                add(value.get(inner), f"{key}.{inner}")
            for name, target in value.items():
                if key == "chrome_url_overrides":
                    add(target, f"chrome_url_overrides.{name}")
            for index, ruleset in enumerate(_as_list(value.get("rule_resources"))):
                if isinstance(ruleset, dict):
                    add(
                        ruleset.get("path"),
                        f"{key}.rule_resources[{index}].path",
                    )
        elif isinstance(value, str) and key in (
            "options_page",
            "devtools_page",
            "sandbox",
        ):
            add(value, key)

    return out


# --------------------------------------------------------------------------
# Rules: manifest shape
# --------------------------------------------------------------------------


def _check_manifest_version(
    manifest: Mapping[str, Any], collector: FindingCollector
) -> None:
    value = manifest.get("manifest_version")
    if value is None:
        collector.add(
            "META-004",
            HIGH,
            "missing manifest_version",
            "manifest_version is missing. Without it Chrome treats the "
            "manifest as Manifest V2.",
            'Add "manifest_version": 3.',
        )
    elif value == 2:
        collector.add(
            "MV2-001",
            HIGH,
            "manifest_version is 2",
            "manifest_version is 2. Chrome no longer accepts Manifest V2 "
            "extensions, so this cannot be loaded in current Chrome and "
            "cannot be published to the Chrome Web Store.",
            "Port to MV3: action instead of browser_action, a service worker "
            "instead of a background page, host_permissions for origins, and "
            "chrome.scripting for injection.",
            context={"manifest_version": 2},
        )
    elif value != 3:
        collector.add(
            "META-004",
            HIGH,
            "missing manifest_version",
            f"manifest_version is {value!r}. MV3 requires the integer 3.",
            'Set "manifest_version": 3.',
        )


def _check_metadata(
    manifest: Mapping[str, Any], collector: FindingCollector
) -> None:
    description = manifest.get("description")
    if not isinstance(description, str) or not description.strip():
        collector.add(
            "META-001",
            HIGH,
            "missing 'description'",
            "description is missing or not a non-empty string. The manifest "
            "schema requires it.",
            "Add a description of at most 132 characters.",
        )
    elif len(description) > 132:
        collector.add(
            "META-002",
            MEDIUM,
            "description longer than 132 characters",
            f"description is {len(description)} characters. The Chrome Web "
            "Store listing field is capped at 132, so this is refused at "
            "upload.",
            f"Shorten it by at least {len(description) - 132} characters.",
            context={"length": len(description), "limit": 132},
        )

    version = manifest.get("version")
    if not isinstance(version, str) or not version:
        collector.add(
            "META-003",
            HIGH,
            "missing or malformed 'version'",
            "version is missing or is not a string. It is required.",
            'Add "version": "1.0.0".',
        )
        return
    if not _VERSION_RE.match(version):
        collector.add(
            "META-003",
            HIGH,
            "missing or malformed 'version'",
            f'version "{version}" is not 1 to 4 dot-separated integers. '
            "Chrome rejects suffixes, a leading v and empty segments.",
            'Use a plain dotted integer version such as "1.2.0".',
            context={"version": version},
        )
        return
    for part in version.split("."):
        if int(part) > 65535:
            collector.add(
                "META-003",
                HIGH,
                "missing or malformed 'version'",
                f'version "{version}" has a segment above the maximum of '
                "65535.",
                "Reduce that segment to 65535 or lower.",
                context={"version": version},
            )
            break


def _check_background(
    manifest: Mapping[str, Any], collector: FindingCollector
) -> None:
    background = manifest.get("background")
    if background is None:
        return
    if not isinstance(background, dict):
        collector.add(
            "BG-003",
            HIGH,
            "background has the wrong shape",
            f"background is a {type(background).__name__}. MV3 expects an "
            'object such as {"service_worker": "background.js"}.',
            'Use {"service_worker": "background.js"}.',
        )
        return
    scripts = background.get("scripts")
    if scripts:
        listed = ", ".join(str(item) for item in _as_list(scripts)) or "?"
        collector.add(
            "BG-001",
            HIGH,
            "background.scripts instead of service_worker",
            f"background.scripts lists {listed}. MV3 ignores the key "
            "entirely, so the background code never runs.",
            "Replace it with background.service_worker pointing at one "
            "worker file.",
            context={"scripts": listed},
        )
    if "persistent" in background:
        collector.add(
            "BG-002",
            MEDIUM,
            "background.persistent is ignored in MV3",
            f"background.persistent is {background.get('persistent')!r}, "
            "which had meaning only for an MV2 background page. A service "
            "worker is always event-driven.",
            "Delete the key and move long-lived state into chrome.storage.",
        )


def _csp_entries(manifest: Mapping[str, Any]) -> list[tuple[str, str]]:
    csp = manifest.get("content_security_policy")
    out: list[tuple[str, str]] = []
    if isinstance(csp, str):
        out.append(("content_security_policy", csp))
    elif isinstance(csp, dict):
        for key, value in csp.items():
            if isinstance(value, str) and value.strip():
                out.append((f"content_security_policy.{key}", value))
    return out


def _parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for chunk in policy.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        directives.setdefault(name, [])
        directives[name].extend(parts[1:])
    return directives


def _effective_script_directive(
    directives: Mapping[str, list[str]]
) -> tuple[str, list[str]]:
    if "script-src" in directives:
        return "script-src", list(directives["script-src"])
    if "default-src" in directives:
        return "default-src", list(directives["default-src"])
    return "script-src", []


def _csp_keyword(source: str) -> str:
    """Normalise a CSP source for comparison.

    Keywords carry their quotes in the policy text -- "'self'",
    "'unsafe-eval'" -- so strip them before comparing.
    """
    return source.strip().strip("'").lower()


_CSP_004_MSG = (
    "content_security_policy must be an object with extension_pages (and "
    "optionally sandbox) string values, or a plain policy string. As "
    "written, no policy is applied and the mistake is easy to miss."
)
_CSP_004_FIX = (
    "Use {\"extension_pages\": \"script-src 'self'; object-src 'self'\"}."
)


def _check_csp(manifest: Mapping[str, Any], collector: FindingCollector) -> None:
    if "content_security_policy" not in manifest:
        return
    csp = manifest.get("content_security_policy")
    if not isinstance(csp, (str, dict)):
        collector.add(
            "CSP-004",
            MEDIUM,
            "content_security_policy is not parseable",
            f"{_CSP_004_MSG} Found a {type(csp).__name__}.",
            _CSP_004_FIX,
        )
        return

    entries = _csp_entries(manifest)
    if not entries:
        collector.add(
            "CSP-004",
            MEDIUM,
            "content_security_policy is not parseable",
            f"{_CSP_004_MSG} Found no usable policy string.",
            _CSP_004_FIX,
        )
        return

    for label, policy in entries:
        directives = _parse_csp(policy)
        if not directives:
            collector.add(
                "CSP-004",
                MEDIUM,
                "content_security_policy is not parseable",
                f"{label} is empty or unparseable.",
                _CSP_004_FIX,
            )
            continue
        directive, sources = _effective_script_directive(directives)

        remote = _unique(source for source in sources if _is_remote_url(source))
        if remote:
            collector.add(
                "CSP-001",
                HIGH,
                "content_security_policy allows remote script",
                f"{label} sets {directive} to include "
                f"{', '.join(remote)}. Scripts may only load from inside the "
                "extension package; a remote script origin is remotely hosted "
                "code.",
                f"Vendor those scripts into the package and reduce "
                f"{directive} to 'self'.",
                context={"directive": directive, "sources": remote},
            )

        unsafe_eval = [
            source for source in sources if _csp_keyword(source) == "unsafe-eval"
        ]
        if unsafe_eval:
            collector.add(
                "CSP-002",
                HIGH,
                "content_security_policy allows 'unsafe-eval'",
                f"{label} sets {directive} to include 'unsafe-eval'. Chrome "
                "refuses to load an MV3 extension that permits eval().",
                "Remove 'unsafe-eval'. Use 'wasm-unsafe-eval' only if you "
                "genuinely need WebAssembly.",
                context={"directive": directive},
            )

        others = _unique(
            source
            for source in sources
            if not _is_remote_url(source)
            and _csp_keyword(source) not in ("self", "unsafe-eval", "wasm-unsafe-eval")
        )
        if others:
            collector.add(
                "CSP-003",
                HIGH,
                "content_security_policy script-src is not 'self'",
                f"{label} allows {', '.join(others)} in {directive}. MV3 "
                "requires script-src to be exactly 'self'.",
                f"Reduce {directive} to 'self'.",
                context={"directive": directive, "sources": others},
            )
        if not unsafe_eval and any(
            _csp_keyword(source) == "wasm-unsafe-eval" for source in sources
        ):
            # Its own rule at medium: Chrome accepts 'wasm-unsafe-eval', so
            # this is a narrowing of the policy rather than a load failure.
            collector.add(
                "CSP-005",
                MEDIUM,
                "content_security_policy enables 'wasm-unsafe-eval'",
                f"{label} widens {directive} beyond 'self' with "
                "'wasm-unsafe-eval'. Chrome accepts it, but it is only needed "
                "for WebAssembly, so a policy that does not ship .wasm is "
                "carrying a needless relaxation.",
                f"Remove 'wasm-unsafe-eval' from {directive} unless the "
                "extension really loads WebAssembly.",
                context={"directive": directive},
            )


def _check_permissions(
    manifest: Mapping[str, Any], collector: FindingCollector
) -> None:
    permissions = manifest.get("permissions")
    if permissions is not None and not isinstance(permissions, list):
        collector.add(
            "PERM-005",
            HIGH,
            "permissions is not an array",
            f"permissions is a {type(permissions).__name__}. It must be an "
            "array of API name strings.",
            'Use "permissions": ["storage"].',
        )
    else:
        for item in _as_list(permissions):
            if isinstance(item, str) and _looks_like_host_pattern(item):
                collector.add(
                    "PERM-001",
                    HIGH,
                    "host pattern in permissions",
                    f'"{item}" in permissions is a host pattern, not an API '
                    "permission. Origins belong in host_permissions; as "
                    "written this grants nothing.",
                    "Move it to host_permissions.",
                    context={"value": item},
                )

    host_permissions = manifest.get("host_permissions")
    if host_permissions is not None and not isinstance(host_permissions, list):
        collector.add(
            "PERM-006",
            HIGH,
            "host_permissions is not an array",
            f"host_permissions is a {type(host_permissions).__name__}. It "
            "must be an array of match patterns.",
            'Use "host_permissions": ["https://example.com/*"].',
        )
    else:
        for item in _as_list(host_permissions):
            if isinstance(item, str) and _looks_like_api_permission(item):
                collector.add(
                    "PERM-002",
                    HIGH,
                    "API permission in host_permissions",
                    f'"{item}" in host_permissions is an API permission name, '
                    "not a match pattern. host_permissions accepts patterns "
                    "only, so the permission is never granted and the API "
                    "call fails at runtime.",
                    "Move it to permissions.",
                    context={"value": item},
                )


def _check_web_accessible_resources(
    manifest: Mapping[str, Any], collector: FindingCollector
) -> None:
    war = manifest.get("web_accessible_resources")
    if war is None:
        return
    if not isinstance(war, list):
        collector.add(
            "WAR-004",
            HIGH,
            "web_accessible_resources is not an array",
            f"web_accessible_resources is a {type(war).__name__}. MV3 "
            "requires an array of objects.",
            'Use [{"resources": ["x.js"], "matches": ["<all_urls>"]}].',
        )
        return
    if war and all(isinstance(item, str) for item in war):
        listed = ", ".join(war[:4])
        collector.add(
            "WAR-001",
            HIGH,
            "web_accessible_resources uses the MV2 array form",
            f"web_accessible_resources is an array of {len(war)} string(s) "
            f"({listed}). That is the MV2 form; MV3 requires an array of "
            "objects carrying resources and matches.",
            'Rewrite as [{"resources": [...], "matches": ["<all_urls>"]}], '
            "with the narrowest matches that work.",
            context={"count": len(war)},
        )
        return

    for index, entry in enumerate(war):
        if not isinstance(entry, dict):
            collector.add(
                "WAR-004",
                HIGH,
                "web_accessible_resources is not an array",
                f"web_accessible_resources[{index}] is a "
                f"{type(entry).__name__}; every entry must be an object.",
                'Use {"resources": [...], "matches": [...]}.',
                context={"index": index},
            )
            continue
        matches = entry.get("matches")
        if matches is None:
            collector.add(
                "WAR-002",
                HIGH,
                "web_accessible_resources entry missing 'matches'",
                f"web_accessible_resources[{index}] has no matches key. "
                "Chrome rejects a manifest whose WAR entries omit it.",
                'Add "matches": ["<all_urls>"], or the narrowest origin list '
                "that works.",
                context={"index": index},
            )
        elif not isinstance(matches, list) or not matches:
            collector.add(
                "WAR-002",
                HIGH,
                "web_accessible_resources entry missing 'matches'",
                f"web_accessible_resources[{index}].matches must be a "
                "non-empty array of match patterns.",
                'Use "matches": ["https://example.com/*"].',
                context={"index": index},
            )
        resources = entry.get("resources")
        if not isinstance(resources, list) or not resources:
            collector.add(
                "WAR-005",
                MEDIUM,
                "web_accessible_resources entry has no resources",
                f"web_accessible_resources[{index}].resources must be a "
                "non-empty array of extension-relative paths.",
                'Use "resources": ["images/logo.png"].',
                context={"index": index},
            )


def _check_dnr_exposure(
    manifest: Mapping[str, Any], collector: FindingCollector
) -> None:
    """Flag DNR ruleset files that are not also web-accessible."""
    dnr = manifest.get("declarative_net_request")
    if not isinstance(dnr, dict):
        return
    exposed: set[str] = set()
    for entry in _as_list(manifest.get("web_accessible_resources")):
        if isinstance(entry, dict):
            for item in _as_list(entry.get("resources")):
                if isinstance(item, str):
                    exposed.add(_relative_url(item))
        elif isinstance(entry, str):
            exposed.add(_relative_url(entry))

    for index, ruleset in enumerate(_as_list(dnr.get("rule_resources"))):
        if not isinstance(ruleset, dict):
            continue
        path = ruleset.get("path")
        if not isinstance(path, str) or not path.strip():
            continue
        path = _relative_url(path)
        if path in exposed:
            continue
        collector.add(
            "WAR-003",
            LOW,
            "declarativeNetRequest rule resource may need to be web-accessible",
            f"{json.dumps(path)} is named in "
            f"declarative_net_request.rule_resources[{index}] but does not "
            "appear in web_accessible_resources. Chrome fetches ruleset files "
            "through the extension's web-accessible resource route. Flagged "
            "as review-risk: this linter does not load Chrome to confirm.",
            "Add the ruleset path to web_accessible_resources with "
            '"matches": ["<all_urls>"], or remove DNR from the manifest.',
            review=True,
            context={"path": path},
        )


def _check_action(manifest: Mapping[str, Any], collector: FindingCollector) -> None:
    for legacy in ("browser_action", "page_action"):
        if legacy in manifest:
            collector.add(
                "ACTION-001",
                HIGH,
                "browser_action / page_action instead of action",
                f"{legacy} is an MV2 key. MV3 merged both into action, and "
                f"Chrome ignores {legacy}, so the toolbar button never "
                "appears.",
                f"Rename {legacy} to action.",
                context={"legacy_key": legacy},
            )


def _match_patterns_of(manifest: Mapping[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for index, entry in enumerate(_as_list(manifest.get("content_scripts"))):
        if not isinstance(entry, dict):
            continue
        for pattern in _as_list(entry.get("matches")):
            if isinstance(pattern, str):
                out.append((f"content_scripts[{index}].matches", pattern))
        for pattern in _as_list(entry.get("exclude_matches")):
            if isinstance(pattern, str):
                out.append((f"content_scripts[{index}].exclude_matches", pattern))
    for index, entry in enumerate(_as_list(manifest.get("web_accessible_resources"))):
        if isinstance(entry, dict):
            for pattern in _as_list(entry.get("matches")):
                if isinstance(pattern, str):
                    out.append(
                        (f"web_accessible_resources[{index}].matches", pattern)
                    )
    for pattern in _as_list(manifest.get("host_permissions")):
        if isinstance(pattern, str):
            out.append(("host_permissions", pattern))
    return out


def _match_pattern_has_no_path(pattern: str) -> bool:
    """True when *pattern* is scheme://host with no path component.

    The path lives in capture group 4.  Group 3 is the optional ``*.`` inside
    the host alternation, so it is None for every ordinary pattern -- reading
    group 3 here would call every valid pattern path-less.
    """
    stripped = pattern.strip()
    if not stripped or stripped.startswith("<"):
        return False
    match = _MATCH_PATTERN_RE.match(stripped)
    if match is None:
        # Not a recognizable pattern at all; do not guess.
        return False
    return match.group(_MATCH_PATTERN_PATH_GROUP) is None


def _check_match_patterns(
    manifest: Mapping[str, Any], collector: FindingCollector
) -> None:
    for label, pattern in _match_patterns_of(manifest):
        if pattern == "<all_urls>":
            collector.add(
                "MATCH-002",
                LOW,
                "<all_urls> where a narrower pattern would do",
                f"{label} uses <all_urls>. Chrome allows it, but injecting "
                "into every origin is the widest request available and "
                "attracts Web Store review scrutiny. (Web Store review "
                "convention, not a runtime error.)",
                "List the specific origins you need, or drop content_scripts "
                "in favour of activeTab plus chrome.scripting.",
                review=True,
                context={"where": label, "pattern": pattern},
            )
            continue
        if _match_pattern_has_no_path(pattern):
            collector.add(
                "MATCH-001",
                HIGH,
                "match pattern with no path",
                f'{label} contains "{pattern}", which has no path component. '
                "A match pattern needs scheme://host/path, so this is "
                f'invalid; "{pattern}/*" is what you meant. An invalid '
                "pattern makes Chrome refuse the whole manifest.",
                f'Change it to "{pattern}/*", or narrow it to the exact path '
                "you inject into.",
                context={"where": label, "pattern": pattern},
            )


def _check_icons(manifest: Mapping[str, Any], collector: FindingCollector) -> None:
    icons = manifest.get("icons")
    if not isinstance(icons, dict) or not icons:
        collector.add(
            "ICON-002",
            MEDIUM,
            "no usable 'icons' key",
            "icons is missing or is not a non-empty object keyed by pixel "
            "size, so there is no 128px image for the store listing.",
            'Add icons with at least "128": "icons/icon128.png".',
        )
        return
    if "128" not in icons:
        collector.add(
            "ICON-001",
            MEDIUM,
            "icons missing the 128px entry",
            "icons has no 128 entry. The Chrome Web Store listing requires a "
            "128x128 icon; Chrome can render its own icon but the listing "
            "cannot.",
            'Add "128": "icons/icon128.png".',
            context={"present": sorted(str(key) for key in icons.keys())},
        )


def _check_minimum_chrome_version(
    manifest: Mapping[str, Any], collector: FindingCollector
) -> None:
    if "minimum_chrome_version" in manifest:
        return
    used: list[tuple[int, str]] = []
    for item in _as_list(manifest.get("permissions")):
        if isinstance(item, str) and item in _MIN_CHROME_FOR_PERMISSION:
            version, label = _MIN_CHROME_FOR_PERMISSION[item]
            used.append((version, f"{label} (permissions: {item})"))
    for item in _as_list(manifest.get("optional_permissions")):
        if isinstance(item, str) and item in _MIN_CHROME_FOR_PERMISSION:
            version, label = _MIN_CHROME_FOR_PERMISSION[item]
            used.append((version, f"{label} (optional_permissions: {item})"))
    if not used:
        return
    highest = max(version for version, _ in used)
    details = "; ".join(f"{label} needs Chrome {version} or newer"
                        for version, label in used)
    collector.add(
        "CHROME-001",
        LOW,
        "minimum_chrome_version absent for a modern API",
        f"minimum_chrome_version is not set, but {details}. Users on older "
        "Chrome will install the extension and hit an undefined API at "
        "runtime.",
        f'Add "minimum_chrome_version": "{highest}".',
        context={"required": highest, "apis": [label for _, label in used]},
    )


# --------------------------------------------------------------------------
# Rules: referenced files
# --------------------------------------------------------------------------


def _check_referenced_files(
    root: str,
    manifest: Mapping[str, Any],
    collector: FindingCollector,
) -> None:
    for relpath, origin in _collect_referenced_files(manifest):
        if not relpath or _is_remote_url(relpath) or _SCHEME_RE.match(relpath):
            continue
        if _is_glob(relpath):
            collector.add(
                "FILE-002",
                LOW,
                "referenced path is a glob or directory",
                f"{origin} points at {json.dumps(relpath)}, which is a glob "
                "pattern or bare directory rather than a concrete file, so "
                "existence cannot be decided statically.",
                "Check by hand that the packaged archive contains the files "
                "this resolves to.",
                context={"origin": origin, "path": relpath},
                dedupe=("glob", relpath),
            )
            continue
        if _entry_exists(root, relpath):
            continue
        collector.add(
            "FILE-001",
            HIGH,
            "referenced file does not exist",
            f"{origin} points at {json.dumps(relpath)}, which is not in the "
            "extension directory. The manifest itself stays valid, so this "
            "shows up only after packaging: the feature is dead, or Chrome "
            "refuses the package.",
            "Add the missing file, or correct the path. Paths resolve "
            "relative to the extension root (the directory holding "
            "manifest.json).",
            context={"origin": origin, "path": relpath},
            dedupe=("missing", relpath),
        )


def _scan_referenced_sources(
    root: str,
    relpaths: Iterable[str],
    collector: FindingCollector,
) -> list[str]:
    """Scan every referenced HTML/JS file once; return extra paths found."""
    extra: list[str] = []
    seen: set[str] = set()
    for relpath in relpaths:
        normalised = os.path.normpath(relpath)
        if normalised in seen:
            continue
        seen.add(normalised)
        lowered = normalised.lower()
        if lowered.endswith((".html", ".htm")):
            extra.extend(_scan_html(root, normalised, collector))
        elif lowered.endswith((".js", ".mjs", ".cjs")):
            _scan_js(root, normalised, collector)
    return extra


def _check_html_references(
    root: str,
    manifest: Mapping[str, Any],
    collector: FindingCollector,
) -> None:
    """Follow references inside HTML pages, reporting the missing ones."""
    queue = [path for path, _ in _collect_referenced_files(manifest)]
    visited: set[str] = set()
    for _ in range(4):  # bounded: pages referencing pages
        discovered = _scan_referenced_sources(root, queue, collector)
        pending: list[str] = []
        for relpath in discovered:
            normalised = os.path.normpath(relpath)
            if normalised in visited:
                continue
            visited.add(normalised)
            if _entry_exists(root, normalised):
                pending.append(normalised)
                continue
            collector.add(
                "FILE-001",
                HIGH,
                "referenced file does not exist",
                f"An extension page references {json.dumps(relpath)}, which "
                "is not in the extension directory. The page loads with a "
                "missing asset and the feature is dead.",
                "Add the file, or fix the reference in the HTML page.",
                file=relpath,
                context={"origin": "HTML reference", "path": relpath},
                dedupe=("missing", relpath),
            )
        if not pending:
            break
        queue = pending


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def resolve_manifest(target: str) -> tuple[str, str]:
    """Return (extension_root, manifest_path) for a directory or file path."""
    path = os.path.abspath(target)
    if os.path.isdir(path):
        return path, os.path.join(path, MANIFEST_FILENAME)
    return os.path.dirname(path), path


@dataclass
class Report:
    root: str
    manifest_path: str
    findings: list[Finding] = field(default_factory=list)
    manifest: Mapping[str, Any] | None = None
    error: str | None = None

    def counts(self) -> dict[str, int]:
        out = {HIGH: 0, MEDIUM: 0, LOW: 0}
        for finding in self.findings:
            out[finding.severity] += 1
        return out

    def at_or_above(self, threshold: str) -> list[Finding]:
        floor = SEVERITY_RANK[threshold]
        return [f for f in self.findings if SEVERITY_RANK[f.severity] >= floor]

    def rules(self) -> list[str]:
        return sorted({finding.rule for finding in self.findings})

    def as_dict(self) -> dict[str, Any]:
        counts = self.counts()
        return {
            "tool": TOOL_NAME,
            "version": __version__,
            "root": self.root,
            "manifest": self.manifest_path,
            "error": self.error,
            "summary": {
                "high": counts[HIGH],
                "medium": counts[MEDIUM],
                "low": counts[LOW],
                "total": len(self.findings),
            },
            "findings": [finding.as_dict() for finding in self.findings],
        }


def lint_extension(target: str) -> Report:
    """Lint the extension at *target* (a directory or a manifest path)."""
    root, manifest_path = resolve_manifest(target)
    report = Report(root=root, manifest_path=manifest_path)

    if not os.path.exists(manifest_path):
        report.error = f"no {MANIFEST_FILENAME} found at {manifest_path}"
        return report

    raw = _read_text(manifest_path)
    if raw is None:
        report.error = f"cannot read {manifest_path}"
        return report

    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        report.error = (
            f"{MANIFEST_FILENAME} is not valid JSON: {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno})"
        )
        return report

    if not isinstance(manifest, dict):
        report.error = (
            f"{MANIFEST_FILENAME} must contain a JSON object, found "
            f"{type(manifest).__name__}"
        )
        return report

    report.manifest = manifest
    collector = FindingCollector()

    _check_manifest_version(manifest, collector)
    _check_metadata(manifest, collector)
    _check_background(manifest, collector)
    _check_csp(manifest, collector)
    _check_permissions(manifest, collector)
    _check_web_accessible_resources(manifest, collector)
    _check_dnr_exposure(manifest, collector)
    _check_action(manifest, collector)
    _check_match_patterns(manifest, collector)
    _check_icons(manifest, collector)
    _check_minimum_chrome_version(manifest, collector)
    _check_referenced_files(root, manifest, collector)
    _check_html_references(root, manifest, collector)

    report.findings = collector.sorted()
    return report


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_SEVERITY_BADGE = {HIGH: "HIGH", MEDIUM: "MED ", LOW: "LOW "}


def render_text(report: Report, threshold: str = LOW) -> str:
    lines: list[str] = []
    findings = report.at_or_above(threshold)
    counts = report.counts()

    lines.append(f"{TOOL_NAME} {__version__}")
    lines.append(f"extension root : {report.root}")
    lines.append(f"manifest       : {report.manifest_path}")
    lines.append(
        f"threshold      : {threshold} -- showing {len(findings)} of "
        f"{len(report.findings)} finding(s)"
    )
    lines.append("")

    if report.error:
        lines.append(f"error: {report.error}")
        return "\n".join(lines) + "\n"

    if not report.findings:
        lines.append("No findings. manifest.json is clean against every rule")
        lines.append("this tool implements (see --list-rules for the list).")
        return "\n".join(lines) + "\n"

    if not findings:
        lines.append(
            f"No findings at or above {threshold}. "
            f"{_plural(len(report.findings), 'lower-severity finding')} "
            "suppressed; add --severity low to see them."
        )
        lines.append("")

    for finding in findings:
        badge = _SEVERITY_BADGE[finding.severity]
        review = " [review convention]" if finding.review else ""
        lines.append(f"{badge} {finding.rule}  {finding.location}{review}")
        lines.append(f"      {finding.message}")
        lines.append(f"      fix: {finding.fix}")
        lines.append("")

    lines.append(
        f"summary: {counts[HIGH]} high, {counts[MEDIUM]} medium, "
        f"{counts[LOW]} low ({len(report.findings)} total)"
    )
    return "\n".join(lines) + "\n"


def _wrap(text: str, width: int) -> list[str]:
    lines: list[str] = []
    current = ""
    for word in text.split():
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current = f"{current} {word}"
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def render_rules() -> str:
    lines = [
        f"{TOOL_NAME} {__version__} -- rule reference",
        "",
        "severity  high   = runtime break, or a hard manifest/package error",
        "          medium = will very likely block or degrade a release",
        "          low    = informational / review-risk",
        "",
        "'review' marks a Chrome Web Store review convention, not a hard",
        "runtime or manifest-validation rule.",
        "",
    ]
    for rule in RULES:
        flag = "review" if rule.review else "hard rule"
        lines.append(
            f"{rule.rule_id}  [{rule.severity:6}] {rule.title}  ({flag})"
        )
        for chunk in _wrap(rule.description, 72):
            lines.append(f"    {chunk}")
        lines.append("")
    lines.append(f"{len(RULES)} rules.")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


class _ArgumentParser(argparse.ArgumentParser):
    """argparse that exits 2 on usage errors (its own convention)."""

    def error(self, message: str):  # pragma: no cover - covered via subprocess
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Static linter for Chrome Manifest V3 extensions. Reads "
            "manifest.json and the files it references, and reports the "
            "mistakes that get an extension rejected from the Chrome Web "
            "Store or break it at runtime."
        ),
        epilog=(
            "exit codes:\n"
            "  0  no findings at or above --severity\n"
            "  1  findings at or above --severity\n"
            "  2  usage error, missing path, or malformed manifest JSON"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="extension directory containing manifest.json, or the path to a "
        "manifest.json",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON on stdout instead of text",
    )
    parser.add_argument(
        "--severity",
        metavar="LEVEL",
        default="all",
        help="minimum severity to report: high, medium, low (default: all)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print nothing when there is nothing to report",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="print the rule reference and exit 0",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list_rules:
        sys.stdout.write(render_rules())
        return 0

    if not args.target:
        parser.print_usage(sys.stderr)
        sys.stderr.write(
            f"{TOOL_NAME}: error: an extension directory or manifest.json "
            "path is required (or use --list-rules)\n"
        )
        return 2

    raw_severity = str(args.severity).strip().lower()
    if raw_severity not in SEVERITY_ALIASES:
        parser.print_usage(sys.stderr)
        sys.stderr.write(
            f"{TOOL_NAME}: error: --severity must be one of high, medium, "
            f"low (got {args.severity!r})\n"
        )
        return 2
    threshold = SEVERITY_ALIASES[raw_severity]

    if not os.path.exists(args.target):
        sys.stderr.write(
            f"{TOOL_NAME}: error: no such file or directory: {args.target}\n"
        )
        return 2

    report = lint_extension(args.target)

    if report.error:
        if args.json:
            payload = report.as_dict()
            payload["threshold"] = threshold
            payload["failing"] = []
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        else:
            sys.stderr.write(f"{TOOL_NAME}: error: {report.error}\n")
        return 2

    failing = report.at_or_above(threshold)

    if args.json:
        payload = report.as_dict()
        payload["threshold"] = threshold
        payload["failing"] = [finding.as_dict() for finding in failing]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    elif args.quiet:
        if failing:
            sys.stdout.write(render_text(report, threshold))
    else:
        sys.stdout.write(render_text(report, threshold))

    return 1 if failing else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

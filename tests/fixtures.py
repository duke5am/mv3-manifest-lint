"""Test fixtures for mv3-manifest-lint.

Nothing here touches ``/tmp`` or ``/sdcard``: scratch extension trees are
created under the repository directory, because writes to those mounts
silently succeed while landing nothing on disk.

Fixtures use obviously fake hostnames (``*.invalid`` is reserved by RFC 2606
and can never resolve) and contain no credentials of any kind.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

SCRATCH_ROOT = os.path.join(PROJECT_ROOT, ".test-scratch")

# --------------------------------------------------------------------------
# A minimal, entirely valid MV3 manifest.
# --------------------------------------------------------------------------

VALID_MANIFEST: dict = {
    "manifest_version": 3,
    "name": "Fixture Extension",
    "version": "1.0.0",
    "description": "A minimal but complete MV3 manifest used by the tests.",
    "icons": {
        "16": "icons/icon16.png",
        "32": "icons/icon32.png",
        "48": "icons/icon48.png",
        "128": "icons/icon128.png",
    },
    "action": {
        "default_title": "Fixture",
        "default_popup": "popup.html",
        "default_icon": {"16": "icons/icon16.png"},
    },
    "background": {"service_worker": "background.js"},
    "permissions": ["storage"],
    "host_permissions": ["https://example.invalid/*"],
    "content_scripts": [
        {
            "matches": ["https://example.invalid/*"],
            "js": ["content/collect.js"],
            "css": ["content/collect.css"],
        }
    ],
    "web_accessible_resources": [
        {
            "resources": ["content/collect.css"],
            "matches": ["https://example.invalid/*"],
        }
    ],
}

# Assets every fixture writes unless a test asks otherwise, so that the only
# finding a test sees is the one it deliberately introduced.
DEFAULT_FILES: dict[str, str] = {
    "background.js": "chrome.runtime.onInstalled.addListener(() => {});\n",
    "popup.html": (
        "<!DOCTYPE html>\n<html><head><title>Fixture</title></head>\n"
        '<body><button id="go">Go</button><script src="popup.js"></script>\n'
        "</body></html>\n"
    ),
    "popup.js": "document.getElementById('go').addEventListener('click', () => {});\n",
    "content/collect.js": "window.fixture = { ready: true };\n",
    "content/collect.css": "#fixture { color: #333; }\n",
    "icons/icon16.png": "fake-png-16\n",
    "icons/icon32.png": "fake-png-32\n",
    "icons/icon48.png": "fake-png-48\n",
    "icons/icon128.png": "fake-png-128\n",
}


def deep_copy(value):
    """A structural copy, so tests can mutate a fixture safely."""
    return json.loads(json.dumps(value))


def write_manifest(root: str, manifest: dict) -> str:
    path = os.path.join(root, "manifest.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return path


def write_raw_manifest(root: str, text: str) -> str:
    path = os.path.join(root, "manifest.json")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def build_extension(
    name: str,
    manifest: dict | None = None,
    extra_files: dict[str, str] | None = None,
    omit_files: tuple[str, ...] = (),
    raw_manifest: str | None = None,
) -> str:
    """Create a scratch extension tree and return its root."""
    root = ScratchDir.make(name)
    files = dict(DEFAULT_FILES)
    if extra_files:
        files.update(extra_files)
    for relpath, content in files.items():
        if relpath in omit_files:
            continue
        target = os.path.join(root, relpath)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(content)
    if raw_manifest is not None:
        write_raw_manifest(root, raw_manifest)
    else:
        write_manifest(root, manifest if manifest is not None else VALID_MANIFEST)
    return root


class ScratchDir:
    """Allocates scratch trees under the project, never under /tmp."""

    _counter = 0

    @classmethod
    def make(cls, name: str) -> str:
        cls._counter += 1
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name)
        path = os.path.join(SCRATCH_ROOT, f"{cls._counter:03d}-{safe}")
        os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def cleanup() -> None:
        shutil.rmtree(SCRATCH_ROOT, ignore_errors=True)


class LintTestCase(unittest.TestCase):
    """Base class that builds fixtures and offers rule-oriented assertions."""

    @classmethod
    def setUpClass(cls) -> None:
        os.makedirs(SCRATCH_ROOT, exist_ok=True)
        # Prove the scratch area really accepts writes.  /tmp and /sdcard
        # return success while storing nothing, so an exit code is not proof.
        probe = os.path.join(SCRATCH_ROOT, ".write-probe")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("probe\n")
        if not os.path.exists(probe):
            raise RuntimeError(
                f"scratch directory {SCRATCH_ROOT} silently dropped a write; "
                "tests cannot run"
            )

    @classmethod
    def tearDownClass(cls) -> None:
        ScratchDir.cleanup()

    # -- helpers -----------------------------------------------------------

    def lint(self, root: str):
        import mv3_manifest_lint as linter

        return linter.lint_extension(root)

    def lint_manifest(self, name: str, manifest: dict, **kwargs):
        root = build_extension(name, manifest=manifest, **kwargs)
        return root, self.lint(root)

    def rules_of(self, report) -> list[str]:
        return sorted({finding.rule for finding in report.findings})

    def assertHasRule(self, report, rule: str, msg: str | None = None):
        found = self.rules_of(report)
        self.assertIn(
            rule,
            found,
            msg
            or f"expected {rule}; got {found or 'no findings'}"
            + self._dump(report),
        )

    def assertNoRule(self, report, rule: str, msg: str | None = None):
        found = self.rules_of(report)
        self.assertNotIn(
            rule, found, msg or f"did not expect {rule}" + self._dump(report)
        )

    def assertNoFindings(self, report, msg: str | None = None):
        self.assertEqual(
            [f"{f.rule}@{f.location}" for f in report.findings],
            [],
            msg
            or "expected zero findings but got "
            + ", ".join(
                f"{f.rule}@{f.location}" for f in report.findings
            ),
        )

    def finding(self, report, rule: str):
        matches = [f for f in report.findings if f.rule == rule]
        self.assertTrue(matches, f"no finding with rule {rule}")
        return matches[0]

    def assertSeverity(self, report, rule: str, severity: str):
        self.assertEqual(self.finding(report, rule).severity, severity)

    def _dump(self, report) -> str:
        if not report.findings:
            return ""
        rendered = "\n".join(
            f"  - {f.rule} [{f.severity}] {f.location}: {f.message}"
            for f in report.findings
        )
        return "\nfindings were:\n" + rendered

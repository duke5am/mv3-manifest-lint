"""CLI contract tests: flags, exit codes and output formats.

These run the real command in a subprocess, because the exit codes and the
stdout/stderr split are the parts a CI pipeline depends on.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

try:  # plain "discover -s tests", where tests/ is on sys.path
    from fixtures import (
        PROJECT_ROOT,
        VALID_MANIFEST,
        LintTestCase,
        build_extension,
        deep_copy,
    )
except ImportError:  # package-style import, e.g. discover with a top-level dir
    from tests.fixtures import (
        PROJECT_ROOT,
        VALID_MANIFEST,
        LintTestCase,
        build_extension,
        deep_copy,
    )

CLI = os.path.join(PROJECT_ROOT, "mv3_manifest_lint.py")


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, CLI, *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=90,
    )


class ExitCodeTest(LintTestCase):
    def test_clean_extension_exits_zero(self):
        root = build_extension("cli-clean")
        done = run_cli(root)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("No findings", done.stdout)

    def test_findings_exit_one(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["manifest_version"] = 2
        root = build_extension("cli-findings", manifest=manifest)
        done = run_cli(root)
        self.assertEqual(done.returncode, 1)
        self.assertIn("MV2-001", done.stdout)

    def test_missing_target_exits_two(self):
        done = run_cli(os.path.join(PROJECT_ROOT, "does-not-exist"))
        self.assertEqual(done.returncode, 2)
        self.assertIn("no such file or directory", done.stderr)

    def test_malformed_json_exits_two(self):
        root = build_extension("cli-malformed", raw_manifest="{not json")
        done = run_cli(root)
        self.assertEqual(done.returncode, 2)
        self.assertIn("not valid JSON", done.stderr)

    def test_no_arguments_exits_two(self):
        done = run_cli()
        self.assertEqual(done.returncode, 2)
        self.assertIn("required", done.stderr)

    def test_bad_severity_exits_two(self):
        root = build_extension("cli-bad-severity")
        done = run_cli(root, "--severity", "critical")
        self.assertEqual(done.returncode, 2)
        self.assertIn("--severity", done.stderr)

    def test_list_rules_exits_zero(self):
        done = run_cli("--list-rules")
        self.assertEqual(done.returncode, 0)
        self.assertIn("rule reference", done.stdout)

    def test_help_exits_zero(self):
        done = run_cli("--help")
        self.assertEqual(done.returncode, 0)
        self.assertIn("exit codes", done.stdout)

    def test_version_exits_zero(self):
        done = run_cli("--version")
        self.assertEqual(done.returncode, 0)
        self.assertIn("mv3-manifest-lint", done.stdout)


class SeverityThresholdTest(LintTestCase):
    """Build one extension with one high and one low finding, then filter."""

    def setUp(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["background"] = {"scripts": ["background.js"]}  # BG-001 high
        manifest["content_scripts"][0]["matches"] = ["<all_urls>"]  # MATCH-002 low
        self.root = build_extension("cli-threshold", manifest=manifest)

    def test_default_threshold_reports_both(self):
        done = run_cli(self.root)
        self.assertEqual(done.returncode, 1)
        self.assertIn("BG-001", done.stdout)
        self.assertIn("MATCH-002", done.stdout)
        self.assertIn("2 total", done.stdout)

    def test_high_threshold_hides_the_low_finding(self):
        done = run_cli(self.root, "--severity", "high")
        self.assertEqual(done.returncode, 1)
        self.assertIn("BG-001", done.stdout)
        self.assertNotIn("MATCH-002", done.stdout)

    def test_medium_threshold_shows_high_and_medium(self):
        done = run_cli(self.root, "--severity", "medium")
        self.assertEqual(done.returncode, 1)
        self.assertIn("BG-001", done.stdout)
        self.assertNotIn("MATCH-002", done.stdout)

    def test_low_threshold_shows_everything(self):
        done = run_cli(self.root, "--severity", "low")
        self.assertEqual(done.returncode, 1)
        self.assertIn("MATCH-002", done.stdout)

    def test_abbreviated_severity_is_accepted(self):
        done = run_cli(self.root, "--severity", "med")
        self.assertEqual(done.returncode, 1)
        self.assertIn("BG-001", done.stdout)

    def test_threshold_below_findings_can_exit_zero(self):
        """Only a low finding, asked for at high severity, is a pass."""
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = ["<all_urls>"]
        root = build_extension("cli-low-only", manifest=manifest)
        strict = run_cli(root, "--severity", "high")
        self.assertEqual(strict.returncode, 0, strict.stdout)
        self.assertIn("No findings at or above high", strict.stdout)
        loose = run_cli(root)
        self.assertEqual(loose.returncode, 1)


class QuietModeTest(LintTestCase):
    def test_quiet_is_silent_on_success(self):
        root = build_extension("cli-quiet-clean")
        done = run_cli(root, "--quiet")
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")

    def test_quiet_still_reports_findings(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["manifest_version"] = 2
        root = build_extension("cli-quiet-bad", manifest=manifest)
        done = run_cli(root, "--quiet")
        self.assertEqual(done.returncode, 1)
        self.assertIn("MV2-001", done.stdout)


class JsonOutputTest(LintTestCase):
    def test_json_is_valid_and_structured(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["manifest_version"] = 2
        root = build_extension("cli-json", manifest=manifest)
        done = run_cli(root, "--json")
        self.assertEqual(done.returncode, 1)
        payload = json.loads(done.stdout)
        self.assertEqual(payload["tool"], "mv3-manifest-lint")
        self.assertIn("version", payload)
        self.assertEqual(payload["error"], None)
        self.assertEqual(payload["threshold"], "low")
        self.assertGreaterEqual(payload["summary"]["total"], 1)

    def test_json_findings_carry_rule_severity_and_fix(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["manifest_version"] = 2
        root = build_extension("cli-json-fields", manifest=manifest)
        payload = json.loads(run_cli(root, "--json").stdout)
        mv2 = [f for f in payload["findings"] if f["rule"] == "MV2-001"]
        self.assertEqual(len(mv2), 1)
        entry = mv2[0]
        for key in ("rule", "severity", "title", "message", "fix", "file",
                    "line", "review"):
            with self.subTest(key=key):
                self.assertIn(key, entry)
        self.assertEqual(entry["severity"], "high")
        self.assertFalse(entry["review"])

    def test_json_clean_run_has_empty_findings(self):
        root = build_extension("cli-json-clean")
        done = run_cli(root, "--json")
        self.assertEqual(done.returncode, 0)
        payload = json.loads(done.stdout)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["summary"]["total"], 0)

    def test_json_reports_parse_errors_with_exit_two(self):
        root = build_extension("cli-json-bad", raw_manifest="}{")
        done = run_cli(root, "--json")
        self.assertEqual(done.returncode, 2)
        payload = json.loads(done.stdout)
        self.assertIsNotNone(payload["error"])
        self.assertIn("not valid JSON", payload["error"])

    def test_json_respects_severity_threshold(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = ["<all_urls>"]
        root = build_extension("cli-json-threshold", manifest=manifest)
        payload = json.loads(run_cli(root, "--json", "--severity", "high").stdout)
        self.assertEqual(payload["failing"], [])
        self.assertTrue(payload["findings"])
        for entry in payload["findings"]:
            self.assertEqual(entry["rule"], "MATCH-002")

    def test_json_locations_are_reported(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["background"] = {"scripts": ["background.js"]}
        root = build_extension("cli-json-location", manifest=manifest)
        payload = json.loads(run_cli(root, "--json").stdout)
        entry = [f for f in payload["findings"] if f["rule"] == "BG-001"][0]
        self.assertEqual(entry["file"], "manifest.json")
        self.assertIsNone(entry["line"])


class TargetFormTest(LintTestCase):
    def test_directory_target(self):
        root = build_extension("cli-dir")
        done = run_cli(root)
        self.assertEqual(done.returncode, 0)

    def test_manifest_file_target(self):
        root = build_extension("cli-file")
        done = run_cli(os.path.join(root, "manifest.json"))
        self.assertEqual(done.returncode, 0)

    def test_manifest_file_target_still_resolves_relative_files(self):
        manifest = deep_copy(VALID_MANIFEST)
        root = build_extension(
            "cli-file-relative", manifest=manifest, omit_files=("background.js",)
        )
        done = run_cli(os.path.join(root, "manifest.json"), "--json")
        self.assertEqual(done.returncode, 1)
        payload = json.loads(done.stdout)
        paths = {
            f["context"]["path"]
            for f in payload["findings"]
            if f["rule"] == "FILE-001"
        }
        self.assertIn("background.js", paths)

    def test_shipped_examples_run_through_the_cli(self):
        good = run_cli(os.path.join(PROJECT_ROOT, "examples", "good"))
        self.assertEqual(good.returncode, 0, good.stdout)
        bad = run_cli(os.path.join(PROJECT_ROOT, "examples", "bad"))
        self.assertEqual(bad.returncode, 1)


class TextOutputTest(LintTestCase):
    def test_text_output_names_the_rule_and_the_fix(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["background"] = {"scripts": ["background.js"]}
        root = build_extension("cli-text", manifest=manifest)
        done = run_cli(root)
        self.assertIn("HIGH BG-001", done.stdout)
        self.assertIn("fix:", done.stdout)
        self.assertIn("summary:", done.stdout)

    def test_review_convention_findings_are_labelled(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = ["<all_urls>"]
        root = build_extension("cli-review-label", manifest=manifest)
        done = run_cli(root)
        self.assertIn("[review convention]", done.stdout)

    def test_clean_output_mentions_no_findings(self):
        root = build_extension("cli-clean-text")
        done = run_cli(root)
        self.assertIn("No findings.", done.stdout)
        self.assertIn("--list-rules", done.stdout)


if __name__ == "__main__":
    unittest.main()

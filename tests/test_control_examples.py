"""Negative control: a correct, store-ready MV3 extension must be silent.

The point of this module is to fail loudly if the linter ever becomes noisy.
``examples/good`` is a real directory tree on disk, not a synthetic manifest,
so this also covers the file-resolution path end to end.

The final test is deliberately harsh: it runs the linter over the *example*
that ships to users and demands exactly zero findings at the default
threshold.
"""

from __future__ import annotations

import json
import os
import unittest

try:  # plain "discover -s tests", where tests/ is on sys.path
    from fixtures import PROJECT_ROOT, LintTestCase
except ImportError:  # package-style import, e.g. discover with a top-level dir
    from tests.fixtures import PROJECT_ROOT, LintTestCase

EXAMPLES = os.path.join(PROJECT_ROOT, "examples")
GOOD = os.path.join(EXAMPLES, "good")
BAD = os.path.join(EXAMPLES, "bad")


class ShippedGoodExampleTest(LintTestCase):
    def setUp(self):
        if not os.path.isdir(GOOD):
            self.skipTest(f"{GOOD} is missing")
        self.report = self.lint(GOOD)

    def test_no_parse_error(self):
        self.assertIsNone(self.report.error)

    def test_zero_findings_at_default_threshold(self):
        self.assertEqual(
            [(f.rule, f.location, f.message) for f in self.report.findings],
            [],
            "examples/good must be completely clean, not nearly clean",
        )

    def test_zero_findings_at_high_threshold(self):
        self.assertEqual(self.report.at_or_above("high"), [])

    def test_zero_findings_at_medium_threshold(self):
        self.assertEqual(self.report.at_or_above("medium"), [])

    def test_zero_findings_at_low_threshold(self):
        self.assertEqual(self.report.at_or_above("low"), [])

    def test_summary_counts_are_all_zero(self):
        counts = self.report.counts()
        self.assertEqual(counts, {"high": 0, "medium": 0, "low": 0})

    def test_manifest_is_parsed_as_a_dict(self):
        self.assertIsInstance(self.report.manifest, dict)
        self.assertEqual(self.report.manifest["manifest_version"], 3)

    def test_every_referenced_file_exists(self):
        manifest = self.report.manifest
        referenced = [
            manifest["background"]["service_worker"],
            manifest["action"]["default_popup"],
            manifest["options_page"],
        ]
        referenced += list(manifest["icons"].values())
        referenced += manifest["content_scripts"][0]["js"]
        referenced += manifest["content_scripts"][0]["css"]
        for relpath in referenced:
            with self.subTest(path=relpath):
                self.assertTrue(
                    os.path.exists(os.path.join(GOOD, relpath)),
                    f"examples/good/{relpath} should exist on disk",
                )

    def test_json_output_is_stable_and_empty(self):
        payload = json.loads(json.dumps(self.report.as_dict()))
        self.assertEqual(payload["summary"]["total"], 0)
        self.assertEqual(payload["findings"], [])


class ShippedBadExampleTest(LintTestCase):
    """The bad example must exercise a broad slice of the rule set."""

    def setUp(self):
        if not os.path.isdir(BAD):
            self.skipTest(f"{BAD} is missing")
        self.report = self.lint(BAD)
        self.rules = set(self.rules_of(self.report))

    def test_no_parse_error(self):
        self.assertIsNone(self.report.error)

    def test_has_many_findings(self):
        self.assertGreaterEqual(len(self.report.findings), 20)

    def test_covers_manifest_version_migration(self):
        for rule in ("MV2-001", "BG-001", "ACTION-001", "WAR-001", "PERM-001",
                     "PERM-002"):
            with self.subTest(rule=rule):
                self.assertIn(rule, self.rules)

    def test_covers_csp_rules(self):
        self.assertIn("CSP-001", self.rules)

    def test_covers_html_rules(self):
        for rule in ("HTML-001", "HTML-002", "HTML-003"):
            with self.subTest(rule=rule):
                self.assertIn(rule, self.rules)

    def test_covers_remote_code_rules(self):
        for rule in ("REMOTE-001", "REMOTE-002", "REMOTE-003"):
            with self.subTest(rule=rule):
                self.assertIn(rule, self.rules)

    def test_covers_metadata_and_icon_rules(self):
        for rule in ("META-002", "META-003", "ICON-001", "MATCH-001",
                     "MATCH-002"):
            with self.subTest(rule=rule):
                self.assertIn(rule, self.rules)

    def test_covers_missing_files(self):
        self.assertIn("FILE-001", self.rules)

    def test_high_severity_dominates(self):
        counts = self.report.counts()
        self.assertGreater(counts["high"], 10)
        self.assertGreater(counts["medium"], 0)
        self.assertGreater(counts["low"], 0)

    def test_no_secrets_are_present_in_findings(self):
        """Fixtures must not look like real credentials."""
        blob = json.dumps(self.report.as_dict()).lower()
        for marker in ("api_key", "apikey", "bearer ", "secret", "password"):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, blob)

    def test_every_finding_has_an_explanation_and_a_fix(self):
        for finding in self.report.findings:
            with self.subTest(rule=finding.rule):
                self.assertTrue(finding.message.strip())
                self.assertTrue(finding.fix.strip())
                self.assertIn(finding.severity, ("high", "medium", "low"))

    def test_every_finding_names_a_known_rule(self):
        import mv3_manifest_lint as linter

        for finding in self.report.findings:
            with self.subTest(rule=finding.rule):
                self.assertIn(finding.rule, linter.RULES_BY_ID)
                registered = linter.RULES_BY_ID[finding.rule]
                self.assertEqual(registered.severity, finding.severity)


class RuleRegistryTest(LintTestCase):
    def test_rule_ids_are_unique(self):
        import mv3_manifest_lint as linter

        ids = [rule.rule_id for rule in linter.RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_has_a_description(self):
        import mv3_manifest_lint as linter

        for rule in linter.RULES:
            with self.subTest(rule=rule.rule_id):
                self.assertTrue(rule.description.strip())
                self.assertTrue(rule.title.strip())
                self.assertIn(rule.severity, ("high", "medium", "low"))

    def test_review_convention_rules_are_marked(self):
        import mv3_manifest_lint as linter

        review_rules = {r.rule_id for r in linter.RULES if r.review}
        self.assertIn("MATCH-002", review_rules)


if __name__ == "__main__":
    unittest.main()

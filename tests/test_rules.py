"""Tests for each lint rule, plus malformed input handling.

Every test starts from a manifest that produces zero findings and changes
exactly one thing, so a failure points at one rule.
"""

from __future__ import annotations

import unittest

try:  # plain "discover -s tests", where tests/ is on sys.path
    from fixtures import (
        DEFAULT_FILES,
        VALID_MANIFEST,
        LintTestCase,
        build_extension,
        deep_copy,
    )
except ImportError:  # package-style import, e.g. discover with a top-level dir
    from tests.fixtures import (
        DEFAULT_FILES,
        VALID_MANIFEST,
        LintTestCase,
        build_extension,
        deep_copy,
    )


class ManifestVersionTest(LintTestCase):
    def test_mv2_is_reported_as_high(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["manifest_version"] = 2
        _, report = self.lint_manifest("mv2", manifest)
        self.assertHasRule(report, "MV2-001")
        self.assertSeverity(report, "MV2-001", "high")
        self.assertIn("no longer accepts Manifest V2", self.finding(report, "MV2-001").message)

    def test_mv3_produces_no_version_finding(self):
        root = build_extension("mv3-ok")
        report = self.lint(root)
        self.assertNoRule(report, "MV2-001")
        self.assertNoRule(report, "META-004")

    def test_missing_manifest_version_is_reported(self):
        manifest = deep_copy(VALID_MANIFEST)
        del manifest["manifest_version"]
        _, report = self.lint_manifest("no-mv", manifest)
        self.assertHasRule(report, "META-004")
        self.assertSeverity(report, "META-004", "high")

    def test_manifest_version_1_is_reported(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["manifest_version"] = 1
        _, report = self.lint_manifest("mv1", manifest)
        self.assertHasRule(report, "META-004")
        self.assertNoRule(report, "MV2-001")


class BackgroundTest(LintTestCase):
    def test_background_scripts_replaces_service_worker(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["background"] = {
            "scripts": ["background.js"],
            "persistent": True,
        }
        _, report = self.lint_manifest("bg-scripts", manifest)
        self.assertHasRule(report, "BG-001")
        self.assertSeverity(report, "BG-001", "high")
        self.assertHasRule(report, "BG-002")
        self.assertSeverity(report, "BG-002", "medium")

    def test_persistent_alone_is_medium(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["background"] = {
            "service_worker": "background.js",
            "persistent": True,
        }
        _, report = self.lint_manifest("bg-persistent", manifest)
        self.assertHasRule(report, "BG-002")
        self.assertNoRule(report, "BG-001")

    def test_persistent_false_is_still_flagged_as_mv2_habits(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["background"] = {
            "service_worker": "background.js",
            "persistent": False,
        }
        _, report = self.lint_manifest("bg-persistent-false", manifest)
        self.assertHasRule(report, "BG-002")

    def test_background_as_string_is_wrong_shape(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["background"] = "background.js"
        _, report = self.lint_manifest("bg-string", manifest)
        self.assertHasRule(report, "BG-003")
        self.assertSeverity(report, "BG-003", "high")

    def test_service_worker_is_clean(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest("bg-clean", manifest)
        self.assertNoRule(report, "BG-001")
        self.assertNoRule(report, "BG-002")
        self.assertNoRule(report, "BG-003")


class ContentSecurityPolicyTest(LintTestCase):
    def test_remote_script_src_is_high(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {
            "extension_pages": (
                "script-src 'self' https://cdn.example.invalid; object-src 'self'"
            )
        }
        _, report = self.lint_manifest("csp-remote", manifest)
        self.assertHasRule(report, "CSP-001")
        self.assertSeverity(report, "CSP-001", "high")

    def test_unsafe_eval_is_high(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {
            "extension_pages": "script-src 'self' 'unsafe-eval'; object-src 'self'"
        }
        _, report = self.lint_manifest("csp-eval", manifest)
        self.assertHasRule(report, "CSP-002")
        self.assertSeverity(report, "CSP-002", "high")

    def test_default_src_fallback_is_checked(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {
            "extension_pages": "default-src 'self' https://cdn.example.invalid"
        }
        _, report = self.lint_manifest("csp-default-src", manifest)
        self.assertHasRule(report, "CSP-001")
        self.assertEqual(
            self.finding(report, "CSP-001").context["directive"], "default-src"
        )

    def test_script_src_localhost_is_not_self(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {
            "extension_pages": "script-src 'self' http://localhost:3000; object-src 'self'"
        }
        _, report = self.lint_manifest("csp-localhost", manifest)
        self.assertHasRule(report, "CSP-001")
        self.assertSeverity(report, "CSP-001", "high")

    def test_wildcard_script_src_is_not_self(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {
            "extension_pages": "script-src 'self' https://*/*; object-src 'self'"
        }
        _, report = self.lint_manifest("csp-wildcard", manifest)
        self.assertHasRule(report, "CSP-001")

    def test_safe_extension_pages_policy_is_clean(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {
            "extension_pages": "script-src 'self'; object-src 'self'"
        }
        _, report = self.lint_manifest("csp-clean", manifest)
        self.assertNoRule(report, "CSP-001")
        self.assertNoRule(report, "CSP-002")
        self.assertNoRule(report, "CSP-003")
        self.assertNoRule(report, "CSP-004")

    def test_string_form_policy_is_accepted(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = "script-src 'self'; object-src 'self'"
        _, report = self.lint_manifest("csp-string", manifest)
        self.assertNoRule(report, "CSP-004")
        self.assertNoRule(report, "CSP-001")

    def test_string_form_remote_is_still_caught(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = (
            "script-src 'self' https://cdn.example.invalid"
        )
        _, report = self.lint_manifest("csp-string-remote", manifest)
        self.assertHasRule(report, "CSP-001")

    def test_unparseable_policy_is_medium(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = 42
        _, report = self.lint_manifest("csp-number", manifest)
        self.assertHasRule(report, "CSP-004")
        self.assertSeverity(report, "CSP-004", "medium")

    def test_empty_object_policy_is_reported(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {}
        _, report = self.lint_manifest("csp-empty", manifest)
        self.assertHasRule(report, "CSP-004")

    def test_wasm_unsafe_eval_has_its_own_medium_rule(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {
            "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
        }
        _, report = self.lint_manifest("csp-wasm", manifest)
        self.assertHasRule(report, "CSP-005")
        self.assertSeverity(report, "CSP-005", "medium")
        self.assertNoRule(report, "CSP-002")
        self.assertNoRule(report, "CSP-003")
        self.assertNoRule(report, "CSP-001")

    def test_unsafe_eval_does_not_also_raise_the_not_self_rule(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {
            "extension_pages": "script-src 'self' 'unsafe-eval'; object-src 'self'"
        }
        _, report = self.lint_manifest("csp-eval-only", manifest)
        self.assertHasRule(report, "CSP-002")
        self.assertNoRule(report, "CSP-003")
        self.assertNoRule(report, "CSP-005")

    def test_duplicate_remote_sources_are_listed_once(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_security_policy"] = {
            "extension_pages": (
                "script-src 'self' https://cdn.example.invalid "
                "https://cdn.example.invalid; object-src 'self'"
            )
        }
        _, report = self.lint_manifest("csp-dup", manifest)
        sources = self.finding(report, "CSP-001").context["sources"]
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources, ["https://cdn.example.invalid"])


class PermissionMixupTest(LintTestCase):
    def test_host_pattern_in_permissions(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = ["storage", "https://example.invalid/*"]
        _, report = self.lint_manifest("perm-host", manifest)
        self.assertHasRule(report, "PERM-001")
        self.assertSeverity(report, "PERM-001", "high")
        self.assertEqual(
            self.finding(report, "PERM-001").context["value"],
            "https://example.invalid/*",
        )

    def test_all_urls_in_permissions(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = ["<all_urls>"]
        _, report = self.lint_manifest("perm-all-urls", manifest)
        self.assertHasRule(report, "PERM-001")

    def test_bare_host_in_permissions(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = ["example.invalid"]
        _, report = self.lint_manifest("perm-bare-host", manifest)
        self.assertHasRule(report, "PERM-001")

    def test_wildcard_host_in_permissions(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = ["*://*.example.invalid/*"]
        _, report = self.lint_manifest("perm-wildcard-host", manifest)
        self.assertHasRule(report, "PERM-001")

    def test_api_permission_in_host_permissions(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["host_permissions"] = ["https://example.invalid/*", "tabs"]
        _, report = self.lint_manifest("perm-api-in-host", manifest)
        self.assertHasRule(report, "PERM-002")
        self.assertSeverity(report, "PERM-002", "high")
        self.assertEqual(
            self.finding(report, "PERM-002").context["value"], "tabs"
        )

    def test_several_api_permissions_in_host_permissions(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["host_permissions"] = ["storage", "downloads", "cookies"]
        _, report = self.lint_manifest("perm-many-api", manifest)
        values = sorted(
            f.context["value"]
            for f in report.findings
            if f.rule == "PERM-002"
        )
        self.assertEqual(values, ["cookies", "downloads", "storage"])

    def test_correct_split_is_clean(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest("perm-clean", manifest)
        self.assertNoRule(report, "PERM-001")
        self.assertNoRule(report, "PERM-002")
        self.assertNoRule(report, "PERM-005")
        self.assertNoRule(report, "PERM-006")

    def test_permissions_not_an_array(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = {"storage": True}
        _, report = self.lint_manifest("perm-object", manifest)
        self.assertHasRule(report, "PERM-005")

    def test_host_permissions_not_an_array(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["host_permissions"] = "https://example.invalid/*"
        _, report = self.lint_manifest("host-perm-string", manifest)
        self.assertHasRule(report, "PERM-006")


class WebAccessibleResourcesTest(LintTestCase):
    def test_mv2_array_form_is_high(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["web_accessible_resources"] = [
            "content/collect.css",
            "icons/icon48.png",
        ]
        _, report = self.lint_manifest("war-mv2", manifest)
        self.assertHasRule(report, "WAR-001")
        self.assertSeverity(report, "WAR-001", "high")
        self.assertEqual(self.finding(report, "WAR-001").context["count"], 2)

    def test_missing_matches_key(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["web_accessible_resources"] = [
            {"resources": ["content/collect.css"]}
        ]
        _, report = self.lint_manifest("war-no-matches", manifest)
        self.assertHasRule(report, "WAR-002")
        self.assertSeverity(report, "WAR-002", "high")

    def test_empty_matches_array(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["web_accessible_resources"] = [
            {"resources": ["content/collect.css"], "matches": []}
        ]
        _, report = self.lint_manifest("war-empty-matches", manifest)
        self.assertHasRule(report, "WAR-002")

    def test_empty_resources_array(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["web_accessible_resources"] = [
            {"resources": [], "matches": ["https://example.invalid/*"]}
        ]
        _, report = self.lint_manifest("war-empty-resources", manifest)
        self.assertHasRule(report, "WAR-005")
        self.assertSeverity(report, "WAR-005", "medium")

    def test_not_an_array(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["web_accessible_resources"] = {"resources": ["a.css"]}
        _, report = self.lint_manifest("war-object", manifest)
        self.assertHasRule(report, "WAR-004")

    def test_correct_mv3_form_is_clean(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest("war-clean", manifest)
        for rule in ("WAR-001", "WAR-002", "WAR-003", "WAR-004", "WAR-005"):
            self.assertNoRule(report, rule)

    def test_dnr_ruleset_not_web_accessible_is_flagged(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["declarative_net_request"] = {
            "rule_resources": [{"id": "blocker", "enabled": True, "path": "rules.json"}]
        }
        root, report = self.lint_manifest(
            "war-dnr", manifest, extra_files={"rules.json": "[]\n"}
        )
        self.assertHasRule(report, "WAR-003")
        self.assertSeverity(report, "WAR-003", "low")
        self.assertTrue(self.finding(report, "WAR-003").review)
        self.assertIn("review-risk", self.finding(report, "WAR-003").message)

    def test_dnr_ruleset_that_is_web_accessible_is_clean(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["declarative_net_request"] = {
            "rule_resources": [{"id": "blocker", "enabled": True, "path": "rules.json"}]
        }
        manifest["web_accessible_resources"] = [
            {
                "resources": ["content/collect.css", "rules.json"],
                "matches": ["https://example.invalid/*"],
            }
        ]
        _, report = self.lint_manifest(
            "war-dnr-ok", manifest, extra_files={"rules.json": "[]\n"}
        )
        self.assertNoRule(report, "WAR-003")


class ActionTest(LintTestCase):
    def test_browser_action_is_high(self):
        manifest = deep_copy(VALID_MANIFEST)
        del manifest["action"]
        manifest["browser_action"] = {"default_popup": "popup.html"}
        _, report = self.lint_manifest("browser-action", manifest)
        self.assertHasRule(report, "ACTION-001")
        self.assertSeverity(report, "ACTION-001", "high")
        self.assertEqual(
            self.finding(report, "ACTION-001").context["legacy_key"],
            "browser_action",
        )

    def test_page_action_is_high(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["page_action"] = {"default_title": "Page"}
        _, report = self.lint_manifest("page-action", manifest)
        self.assertHasRule(report, "ACTION-001")
        self.assertEqual(
            self.finding(report, "ACTION-001").context["legacy_key"],
            "page_action",
        )

    def test_both_legacy_keys_are_reported_separately(self):
        manifest = deep_copy(VALID_MANIFEST)
        del manifest["action"]
        manifest["browser_action"] = {"default_popup": "popup.html"}
        manifest["page_action"] = {"default_title": "Page"}
        _, report = self.lint_manifest("both-actions", manifest)
        hits = [f for f in report.findings if f.rule == "ACTION-001"]
        self.assertEqual(len(hits), 2)

    def test_action_is_clean(self):
        root = build_extension("action-clean")
        report = self.lint(root)
        self.assertNoRule(report, "ACTION-001")


class MatchPatternTest(LintTestCase):
    def test_host_without_path_is_high(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = ["https://example.invalid"]
        _, report = self.lint_manifest("match-no-path", manifest)
        self.assertHasRule(report, "MATCH-001")
        self.assertSeverity(report, "MATCH-001", "high")
        self.assertIn("/*", self.finding(report, "MATCH-001").fix)

    def test_host_with_slash_star_is_valid(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = ["https://example.invalid/*"]
        _, report = self.lint_manifest("match-with-path", manifest)
        self.assertNoRule(report, "MATCH-001")

    def test_deep_path_is_valid(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = [
            "https://example.invalid/app/*"
        ]
        _, report = self.lint_manifest("match-deep", manifest)
        self.assertNoRule(report, "MATCH-001")

    def test_subdomain_wildcard_with_path_is_valid(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = [
            "https://*.example.invalid/*"
        ]
        _, report = self.lint_manifest("match-subdomain", manifest)
        self.assertNoRule(report, "MATCH-001")

    def test_scheme_wildcard_without_path_is_high(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = ["*://*"]
        _, report = self.lint_manifest("match-scheme-wildcard", manifest)
        self.assertHasRule(report, "MATCH-001")

    def test_host_permissions_pattern_is_checked_too(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["host_permissions"] = ["https://example.invalid"]
        _, report = self.lint_manifest("match-host-perm", manifest)
        self.assertHasRule(report, "MATCH-001")

    def test_war_matches_is_checked_too(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["web_accessible_resources"][0]["matches"] = [
            "https://example.invalid"
        ]
        _, report = self.lint_manifest("match-war", manifest)
        self.assertHasRule(report, "MATCH-001")

    def test_all_urls_is_a_low_review_flag(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = ["<all_urls>"]
        _, report = self.lint_manifest("match-all-urls", manifest)
        self.assertHasRule(report, "MATCH-002")
        self.assertSeverity(report, "MATCH-002", "low")
        self.assertTrue(self.finding(report, "MATCH-002").review)
        self.assertNoRule(report, "MATCH-001")

    def test_all_urls_does_not_block_a_high_threshold_run(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = ["<all_urls>"]
        _, report = self.lint_manifest("match-all-urls-only", manifest)
        self.assertEqual(report.at_or_above("high"), [])

    def test_file_scheme_without_path_is_high(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["matches"] = ["file://"]
        root, report = self.lint_manifest("match-file", manifest)
        # "file://" is not a valid pattern and is not matched by the pattern
        # regex at all, so the rule stays silent rather than guessing.
        self.assertNoRule(report, "MATCH-001")


class MetadataTest(LintTestCase):
    def test_missing_description(self):
        manifest = deep_copy(VALID_MANIFEST)
        del manifest["description"]
        _, report = self.lint_manifest("no-description", manifest)
        self.assertHasRule(report, "META-001")
        self.assertSeverity(report, "META-001", "high")

    def test_empty_description_is_reported(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["description"] = "   "
        _, report = self.lint_manifest("blank-description", manifest)
        self.assertHasRule(report, "META-001")

    def test_description_over_132_is_medium(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["description"] = "x" * 133
        _, report = self.lint_manifest("long-description", manifest)
        self.assertHasRule(report, "META-002")
        self.assertSeverity(report, "META-002", "medium")
        self.assertEqual(self.finding(report, "META-002").context["length"], 133)

    def test_description_of_exactly_132_is_accepted(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["description"] = "x" * 132
        _, report = self.lint_manifest("description-132", manifest)
        self.assertNoRule(report, "META-002")
        self.assertNoRule(report, "META-001")

    def test_missing_version(self):
        manifest = deep_copy(VALID_MANIFEST)
        del manifest["version"]
        _, report = self.lint_manifest("no-version", manifest)
        self.assertHasRule(report, "META-003")
        self.assertSeverity(report, "META-003", "high")

    def test_version_with_prerelease_suffix(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["version"] = "1.2.3-beta.1"
        _, report = self.lint_manifest("version-suffix", manifest)
        self.assertHasRule(report, "META-003")

    def test_version_with_leading_v(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["version"] = "v1.2"
        _, report = self.lint_manifest("version-leading-v", manifest)
        self.assertHasRule(report, "META-003")

    def test_version_with_five_segments(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["version"] = "1.2.3.4.5"
        _, report = self.lint_manifest("version-five", manifest)
        self.assertHasRule(report, "META-003")

    def test_version_with_empty_segment(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["version"] = "1..2"
        _, report = self.lint_manifest("version-empty-segment", manifest)
        self.assertHasRule(report, "META-003")

    def test_version_as_number(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["version"] = 1.0
        _, report = self.lint_manifest("version-number", manifest)
        self.assertHasRule(report, "META-003")

    def test_version_segment_above_65535(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["version"] = "1.0.70000"
        _, report = self.lint_manifest("version-too-big", manifest)
        self.assertHasRule(report, "META-003")

    def test_four_segment_version_is_valid(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["version"] = "1.2.3.4"
        _, report = self.lint_manifest("version-four", manifest)
        self.assertNoRule(report, "META-003")

    def test_single_segment_version_is_valid(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["version"] = "7"
        _, report = self.lint_manifest("version-one", manifest)
        self.assertNoRule(report, "META-003")


class IconTest(LintTestCase):
    def test_missing_128_entry_is_medium(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["icons"] = {"16": "icons/icon16.png", "48": "icons/icon48.png"}
        _, report = self.lint_manifest("icons-no-128", manifest)
        self.assertHasRule(report, "ICON-001")
        self.assertSeverity(report, "ICON-001", "medium")
        self.assertEqual(
            self.finding(report, "ICON-001").context["present"], ["16", "48"]
        )

    def test_missing_icons_key_is_reported(self):
        manifest = deep_copy(VALID_MANIFEST)
        del manifest["icons"]
        _, report = self.lint_manifest("icons-missing", manifest)
        self.assertHasRule(report, "ICON-002")
        self.assertSeverity(report, "ICON-002", "medium")

    def test_icons_as_string_is_reported(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["icons"] = "icons/icon128.png"
        _, report = self.lint_manifest("icons-string", manifest)
        self.assertHasRule(report, "ICON-002")

    def test_icons_with_128_is_clean(self):
        root = build_extension("icons-ok")
        report = self.lint(root)
        self.assertNoRule(report, "ICON-001")
        self.assertNoRule(report, "ICON-002")


class MinimumChromeVersionTest(LintTestCase):
    def test_offscreen_permission_without_minimum_version(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = ["storage", "offscreen"]
        _, report = self.lint_manifest("chrome-offscreen", manifest)
        self.assertHasRule(report, "CHROME-001")
        self.assertSeverity(report, "CHROME-001", "low")
        self.assertEqual(self.finding(report, "CHROME-001").context["required"], 109)

    def test_side_panel_permission_without_minimum_version(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = ["storage", "sidePanel"]
        _, report = self.lint_manifest("chrome-sidepanel", manifest)
        self.assertHasRule(report, "CHROME-001")
        self.assertEqual(self.finding(report, "CHROME-001").context["required"], 114)

    def test_user_scripts_permission_without_minimum_version(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = ["storage", "userScripts"]
        _, report = self.lint_manifest("chrome-userscripts", manifest)
        self.assertHasRule(report, "CHROME-001")
        self.assertEqual(self.finding(report, "CHROME-001").context["required"], 120)

    def test_minimum_version_present_silences_the_rule(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = ["storage", "offscreen"]
        manifest["minimum_chrome_version"] = "109"
        _, report = self.lint_manifest("chrome-min-set", manifest)
        self.assertNoRule(report, "CHROME-001")

    def test_ordinary_permissions_do_not_trigger_the_rule(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["permissions"] = ["storage", "tabs", "alarms", "scripting"]
        _, report = self.lint_manifest("chrome-ordinary", manifest)
        self.assertNoRule(report, "CHROME-001")

    def test_optional_permissions_are_considered(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["optional_permissions"] = ["userScripts"]
        _, report = self.lint_manifest("chrome-optional", manifest)
        self.assertHasRule(report, "CHROME-001")
        self.assertIn("optional_permissions", self.finding(report, "CHROME-001").message)


class MissingFileTest(LintTestCase):
    def test_missing_service_worker(self):
        manifest = deep_copy(VALID_MANIFEST)
        root, report = self.lint_manifest(
            "file-worker", manifest, omit_files=("background.js",)
        )
        self.assertHasRule(report, "FILE-001")
        self.assertSeverity(report, "FILE-001", "high")
        finding = self.finding(report, "FILE-001")
        self.assertEqual(finding.context["origin"], "background.service_worker")
        self.assertEqual(finding.context["path"], "background.js")

    def test_missing_content_script(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "file-content", manifest, omit_files=("content/collect.js",)
        )
        self.assertHasRule(report, "FILE-001")
        self.assertEqual(
            self.finding(report, "FILE-001").context["origin"],
            "content_scripts[0].js",
        )

    def test_missing_content_script_css(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "file-content-css", manifest, omit_files=("content/collect.css",)
        )
        self.assertHasRule(report, "FILE-001")

    def test_missing_icon(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "file-icon", manifest, omit_files=("icons/icon128.png",)
        )
        self.assertHasRule(report, "FILE-001")
        self.assertIn("icons[128]", self.finding(report, "FILE-001").context["origin"])

    def test_missing_popup(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "file-popup", manifest, omit_files=("popup.html", "popup.js")
        )
        origins = {
            f.context["origin"]
            for f in report.findings
            if f.rule == "FILE-001"
        }
        self.assertIn("action.default_popup", origins)

    def test_same_missing_file_is_reported_once(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"].append(
            {
                "matches": ["https://example.invalid/*"],
                "js": ["content/collect.js"],
            }
        )
        _, report = self.lint_manifest(
            "file-dedupe", manifest, omit_files=("content/collect.js",)
        )
        hits = [
            f
            for f in report.findings
            if f.rule == "FILE-001" and f.context["path"] == "content/collect.js"
        ]
        self.assertEqual(len(hits), 1)

    def test_missing_file_referenced_from_html(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "file-html-ref", manifest, omit_files=("popup.js",)
        )
        hits = [
            f
            for f in report.findings
            if f.rule == "FILE-001" and f.file == "popup.js"
        ]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].context["origin"], "HTML reference")

    def test_glob_reference_is_low_not_missing(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["js"] = ["content/*.js"]
        _, report = self.lint_manifest("file-glob", manifest)
        self.assertHasRule(report, "FILE-002")
        self.assertSeverity(report, "FILE-002", "low")
        self.assertNoRule(report, "FILE-001")

    def test_all_files_present_is_clean(self):
        root = build_extension("file-clean")
        report = self.lint(root)
        self.assertNoRule(report, "FILE-001")
        self.assertNoRule(report, "FILE-002")

    def test_remote_reference_is_not_treated_as_a_missing_file(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["content_scripts"][0]["js"] = [
            "https://cdn.example.invalid/remote.js"
        ]
        _, report = self.lint_manifest("file-remote", manifest)
        self.assertNoRule(report, "FILE-001")

    def test_dotted_reference_is_normalised(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["background"] = {"service_worker": "./background.js"}
        _, report = self.lint_manifest("file-dot-slash", manifest)
        self.assertNoRule(report, "FILE-001")
        self.assertNoRule(report, "BG-001")


class RemoteCodeTest(LintTestCase):
    def test_import_scripts_remote(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-importscripts",
            manifest,
            extra_files={
                "background.js": (
                    "importScripts('https://cdn.example.invalid/x.js');\n"
                )
            },
        )
        self.assertHasRule(report, "REMOTE-001")
        self.assertSeverity(report, "REMOTE-001", "high")
        self.assertEqual(self.finding(report, "REMOTE-001").line, 1)

    def test_import_scripts_relative_is_clean(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-importscripts-local",
            manifest,
            extra_files={
                "background.js": "importScripts('lib/vendor.js');\n",
                "lib/vendor.js": "self.vendor = true;\n",
            },
        )
        self.assertNoRule(report, "REMOTE-001")

    def test_dynamic_import_remote(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-dynamic-import",
            manifest,
            extra_files={
                "background.js": (
                    "async function boot() {\n"
                    "  const mod = await import('https://cdn.example.invalid/m.js');\n"
                    "  return mod;\n"
                    "}\n"
                )
            },
        )
        self.assertHasRule(report, "REMOTE-002")
        self.assertSeverity(report, "REMOTE-002", "high")
        self.assertEqual(self.finding(report, "REMOTE-002").line, 2)

    def test_dynamic_import_relative_is_clean(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-dynamic-local",
            manifest,
            extra_files={
                "background.js": "const mod = import('./lib/local.js');\n",
                "lib/local.js": "export const ready = true;\n",
            },
        )
        self.assertNoRule(report, "REMOTE-002")

    def test_eval_in_service_worker(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-eval",
            manifest,
            extra_files={"background.js": "const parsed = eval('({' + '})');\n"},
        )
        self.assertHasRule(report, "REMOTE-003")
        self.assertSeverity(report, "REMOTE-003", "high")
        self.assertEqual(self.finding(report, "REMOTE-003").context["construct"], "eval")

    def test_new_function_in_service_worker(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-new-function",
            manifest,
            extra_files={"background.js": "const f = new Function('a', 'return a');\n"},
        )
        self.assertHasRule(report, "REMOTE-003")
        self.assertEqual(
            self.finding(report, "REMOTE-003").context["construct"], "new Function"
        )

    def test_eval_in_content_script(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-eval-content",
            manifest,
            extra_files={"content/collect.js": "const v = eval('1 + 1');\n"},
        )
        self.assertHasRule(report, "REMOTE-003")
        self.assertEqual(self.finding(report, "REMOTE-003").file, "content/collect.js")

    def test_member_named_eval_is_not_flagged(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-eval-false-positive",
            manifest,
            extra_files={
                "background.js": (
                    "const options = { evaluate(input) { return input; } };\n"
                    "options.evaluate('x');\n"
                    "function evaluateLater() {}\n"
                )
            },
        )
        self.assertNoRule(report, "REMOTE-003")

    def test_html_script_is_scanned_for_remote_code(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-in-html-js",
            manifest,
            extra_files={
                "popup.js": "importScripts('https://cdn.example.invalid/a.js');\n"
            },
        )
        self.assertHasRule(report, "REMOTE-001")
        self.assertEqual(self.finding(report, "REMOTE-001").file, "popup.js")

    def test_unreferenced_js_is_not_scanned(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "remote-unreferenced",
            manifest,
            extra_files={"vendor/unused.js": "eval('nope');\n"},
        )
        self.assertNoRule(report, "REMOTE-003")

    def test_clean_service_worker_has_no_remote_findings(self):
        root = build_extension("remote-clean")
        report = self.lint(root)
        for rule in ("REMOTE-001", "REMOTE-002", "REMOTE-003"):
            self.assertNoRule(report, rule)


class HtmlScanTest(LintTestCase):
    def test_remote_script_tag(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-remote-script",
            manifest,
            extra_files={
                "popup.html": (
                    "<!DOCTYPE html>\n<html><head>\n"
                    '<script src="https://cdn.example.invalid/lib.js"></script>\n'
                    "</head><body></body></html>\n"
                )
            },
        )
        self.assertHasRule(report, "HTML-001")
        self.assertSeverity(report, "HTML-001", "high")
        self.assertEqual(self.finding(report, "HTML-001").line, 3)
        self.assertEqual(self.finding(report, "HTML-001").file, "popup.html")

    def test_protocol_relative_remote_script(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-protocol-relative",
            manifest,
            extra_files={
                "popup.html": (
                    '<!DOCTYPE html><html><body>\n'
                    '<script src="//cdn.example.invalid/lib.js"></script>\n'
                    "</body></html>\n"
                )
            },
        )
        self.assertHasRule(report, "HTML-001")

    def test_inline_script_block(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-inline-script",
            manifest,
            extra_files={
                "popup.html": (
                    "<!DOCTYPE html><html><body>\n"
                    "<script>console.log('inline');</script>\n"
                    "</body></html>\n"
                )
            },
        )
        self.assertHasRule(report, "HTML-002")
        self.assertSeverity(report, "HTML-002", "high")
        self.assertEqual(self.finding(report, "HTML-002").line, 2)

    def test_inline_event_handler(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-inline-handler",
            manifest,
            extra_files={
                "popup.html": (
                    "<!DOCTYPE html><html><body>\n"
                    '<button onclick="go()">Go</button>\n'
                    "</body></html>\n"
                )
            },
        )
        self.assertHasRule(report, "HTML-003")
        self.assertSeverity(report, "HTML-003", "high")
        self.assertEqual(self.finding(report, "HTML-003").line, 2)

    def test_inline_handler_in_commented_out_markup_is_ignored(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-commented-handler",
            manifest,
            extra_files={
                "popup.html": (
                    "<!DOCTYPE html><html><body>\n"
                    "<!-- <button onclick=\"neverRuns()\">Old</button> -->\n"
                    '<button id="go" type="button">Go</button>\n'
                    '<script src="popup.js"></script>\n'
                    "</body></html>\n"
                )
            },
        )
        self.assertNoRule(report, "HTML-003")

    def test_multiple_inline_handlers_are_each_reported(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-two-handlers",
            manifest,
            extra_files={
                "popup.html": (
                    "<!DOCTYPE html><html><body>\n"
                    '<button onclick="a()">A</button>\n'
                    '<p onmouseover="b()">B</p>\n'
                    "</body></html>\n"
                )
            },
        )
        hits = [f for f in report.findings if f.rule == "HTML-003"]
        self.assertEqual(len(hits), 2)
        self.assertEqual(sorted(f.line for f in hits), [2, 3])

    def test_remote_stylesheet_is_low_and_review_only(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-remote-css",
            manifest,
            extra_files={
                "popup.html": (
                    "<!DOCTYPE html><html><head>\n"
                    '<link rel="stylesheet" href="https://fonts.example.invalid/x.css">\n'
                    "</head><body></body></html>\n"
                )
            },
        )
        self.assertHasRule(report, "HTML-004")
        self.assertSeverity(report, "HTML-004", "low")
        self.assertTrue(self.finding(report, "HTML-004").review)
        self.assertEqual(report.at_or_above("high"), [])

    def test_local_script_and_stylesheet_are_clean(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-clean",
            manifest,
            extra_files={
                "popup.html": (
                    "<!DOCTYPE html><html><head>\n"
                    '<link rel="stylesheet" href="popup.css">\n'
                    "</head><body>\n"
                    '<script src="popup.js"></script>\n'
                    "</body></html>\n"
                ),
                "popup.css": "body { color: #111; }\n",
            },
        )
        for rule in ("HTML-001", "HTML-002", "HTML-003", "HTML-004"):
            self.assertNoRule(report, rule)

    def test_options_page_html_is_scanned(self):
        manifest = deep_copy(VALID_MANIFEST)
        manifest["options_page"] = "options.html"
        _, report = self.lint_manifest(
            "html-options",
            manifest,
            extra_files={
                "options.html": (
                    '<!DOCTYPE html><html><body><script src="https://cdn.example.invalid/o.js"></script>\n'
                    "</body></html>\n"
                )
            },
        )
        self.assertHasRule(report, "HTML-001")
        self.assertEqual(self.finding(report, "HTML-001").file, "options.html")

    def test_self_closing_script_tag(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-self-closing",
            manifest,
            extra_files={
                "popup.html": (
                    "<!DOCTYPE html><html><body>\n"
                    '<script src="https://cdn.example.invalid/a.js" />\n'
                    "</body></html>\n"
                )
            },
        )
        self.assertHasRule(report, "HTML-001")

    def test_fake_virtual_host_src_is_treated_as_remote(self):
        manifest = deep_copy(VALID_MANIFEST)
        _, report = self.lint_manifest(
            "html-https-scheme",
            manifest,
            extra_files={
                "popup.html": (
                    "<!DOCTYPE html><html><body>\n"
                    '<script src="https://example.invalid/a.js"></script>\n'
                    "</body></html>\n"
                )
            },
        )
        self.assertHasRule(report, "HTML-001")


class MalformedInputTest(LintTestCase):
    def test_invalid_json_is_a_parse_error(self):
        root = build_extension(
            "malformed-json", raw_manifest='{"manifest_version": 3,}'
        )
        report = self.lint(root)
        self.assertIsNotNone(report.error)
        self.assertIn("not valid JSON", report.error)
        self.assertEqual(report.findings, [])

    def test_truncated_json_reports_a_line_number(self):
        root = build_extension(
            "malformed-truncated",
            raw_manifest='{\n  "manifest_version": 3,\n  "name": "x"\n',
        )
        report = self.lint(root)
        self.assertIsNotNone(report.error)
        self.assertIn("line", report.error)

    def test_json_array_is_a_parse_error(self):
        root = build_extension("malformed-array", raw_manifest="[1, 2, 3]")
        report = self.lint(root)
        self.assertIsNotNone(report.error)
        self.assertIn("JSON object", report.error)

    def test_json_string_is_a_parse_error(self):
        root = build_extension("malformed-string", raw_manifest='"manifest"')
        report = self.lint(root)
        self.assertIsNotNone(report.error)
        self.assertIn("JSON object", report.error)

    def test_empty_file_is_a_parse_error(self):
        root = build_extension("malformed-empty", raw_manifest="")
        report = self.lint(root)
        self.assertIsNotNone(report.error)

    def test_missing_manifest_is_an_error(self):
        manifest = deep_copy(VALID_MANIFEST)
        root = build_extension("no-manifest", manifest)
        import os

        os.remove(os.path.join(root, "manifest.json"))
        report = self.lint(root)
        self.assertIsNotNone(report.error)
        self.assertIn("no manifest.json", report.error)

    def test_error_report_serialises_to_json(self):
        root = build_extension("malformed-json-out", raw_manifest="{oops")
        report = self.lint(root)
        payload = report.as_dict()
        self.assertIsNotNone(payload["error"])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["summary"]["total"], 0)


class MigrationPathTest(LintTestCase):
    """The MV2 -> MV3 cases a migrating extension actually hits."""

    MV2_MANIFEST = {
        "manifest_version": 2,
        "name": "Legacy Extension",
        "version": "2.4.1",
        "description": "A Manifest V2 extension used as migration test input.",
        "icons": {"16": "icons/icon16.png", "128": "icons/icon128.png"},
        "browser_action": {"default_popup": "popup.html"},
        "background": {"scripts": ["background.js"], "persistent": True},
        "permissions": ["storage", "https://example.invalid/*", "tabs"],
        "content_scripts": [
            {
                "matches": ["https://example.invalid/*"],
                "js": ["content/collect.js"],
                "css": ["content/collect.css"],
            }
        ],
        "web_accessible_resources": ["content/collect.css"],
    }

    def setUp(self):
        self.root = build_extension(
            "mv2-migration",
            manifest=deep_copy(self.MV2_MANIFEST),
            extra_files={
                "background.js": "chrome.browserAction.onClicked.addListener(() => {});\n",
                "popup.html": (
                    '<!DOCTYPE html><html><body><script src="popup.js"></script>\n'
                    "</body></html>\n"
                ),
                "popup.js": "document.title = 'legacy';\n",
            },
        )
        self.report = self.lint(self.root)

    def test_reports_every_mv2_shape(self):
        for rule in (
            "MV2-001",
            "BG-001",
            "BG-002",
            "ACTION-001",
            "WAR-001",
            "PERM-001",
        ):
            with self.subTest(rule=rule):
                self.assertHasRule(self.report, rule)

    def test_mv2_migration_has_no_file_findings(self):
        self.assertNoRule(self.report, "FILE-001")

    def test_mv2_migration_has_no_remote_code_findings(self):
        self.assertNoRule(self.report, "REMOTE-001")
        self.assertNoRule(self.report, "REMOTE-002")
        self.assertNoRule(self.report, "REMOTE-003")

    def test_mv2_migration_is_not_clean_at_high_threshold(self):
        self.assertTrue(self.report.at_or_above("high"))

    def test_migrated_manifest_becomes_clean(self):
        migrated = deep_copy(self.MV2_MANIFEST)
        migrated["manifest_version"] = 3
        migrated.pop("browser_action")
        migrated["action"] = {"default_popup": "popup.html"}
        migrated["background"] = {"service_worker": "background.js"}
        migrated["permissions"] = ["storage", "tabs"]
        migrated["host_permissions"] = ["https://example.invalid/*"]
        migrated["web_accessible_resources"] = [
            {
                "resources": ["content/collect.css"],
                "matches": ["https://example.invalid/*"],
            }
        ]
        root = build_extension(
            "mv2-migrated",
            manifest=migrated,
            extra_files={
                "background.js": "chrome.action.onClicked.addListener(() => {});\n",
                "popup.html": (
                    '<!DOCTYPE html><html><body><script src="popup.js"></script>\n'
                    "</body></html>\n"
                ),
                "popup.js": "document.title = 'migrated';\n",
            },
        )
        report = self.lint(root)
        self.assertNoFindings(report)


if __name__ == "__main__":
    unittest.main()

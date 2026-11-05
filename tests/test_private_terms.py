"""Synthetic boundary, report, history and real-CLI privacy regressions."""
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import unittest

import release_check as rc
import test_release_check as fixtures


class BoundaryTests(unittest.TestCase):
    def hits(self, term, text, encoding="utf-8", path="sample.txt"):
        scanner = rc.Scanner([term])
        scanner.text(text.encode(encoding), "tree", path)
        return [f for f in scanner.findings if f["kind"] == "denylist"]

    def test_words_and_separate_components_block(self):
        cases = ["cat", "CAT", "Cat", "(cat)", "cat's", "cat’s", "can't-cat",
                 "cat_file", "file_cat", "file_cat_name", "cat-file", "file-cat",
                 "cat.txt", "file.cat.txt", "/cat/", "C:\\cat\\file.txt",
                 "https://cat.example.org/cat?name=cat#cat", ('cat@' + 'example.org'),
                 ('user' + '@cat.example.org'), ('user' + ('+cat' + '@example.org')), "cat2", "2cat",
                 "getCatValue", "getCATValue", "catFood", "wildCat", "HTTPcat",
                 "HTTPCat", "CATValue", "catHTTP", "getCat", "caT", "sCATter"]
        for text in cases:
            with self.subTest(text=text):
                hits = self.hits("cat", text)
                self.assertTrue(hits)
                self.assertTrue(all(not f.get("reviewable") for f in hits))
                self.assertTrue(all(not f["reviewed"] for f in hits))

    def test_only_longer_letter_components_are_reviewable(self):
        cases = ["cats", "wildcat", "scatter", "SCATTER", "scattering",
                 "écaté", "猫cat犬", "_scatter_", "scatter.txt", "/wildcat/",
                 "https://scatter.example.org/wildcat", ('wildc' + ('at@e' + 'xample.org')),
                 "getScatterValue", "wildcats_food"]
        for text in cases:
            with self.subTest(text=text):
                hits = self.hits("cat", text)
                self.assertTrue(hits)
                self.assertTrue(all(f.get("reviewable") for f in hits))
                self.assertTrue(all(not f["reviewed"] for f in hits))

    def test_unicode_letters_case_and_uncertain_marks(self):
        for term, text, reviewable in [("élan", "ÉLAN", False),
                                       ("élan", "mélange", True),
                                       ("élan", "élan_file", False),
                                       ("猫", "猫_file", False), ("猫", "猫咪", True),
                                       ("cat", "cat\u0301s", False),
                                       ("cat", "x\u0301caty", False),
                                       ("cat", "\u0301cat", False),
                                       ("cat", "cat\u200ds", False),
                                       ("cat", "x\ufffdcaty", False),
                                       ("i", "İ", False), ("i", "mİx", True),
                                       ("i", "mİValue", False)]:
            with self.subTest(term=term, text=text):
                hits = self.hits(term, text)
                self.assertTrue(hits)
                self.assertEqual(all(f.get("reviewable", False) for f in hits), reviewable)
        scanner = rc.Scanner(["cat"])
        scanner.text(b"xcat\xff", "tree", "sample.txt")
        self.assertTrue(all(not f.get("reviewable") for f in scanner.findings))

    def test_utf16_preserves_boundaries_lines_and_case(self):
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding):
                hits = self.hits("larch", "blank\noverlarch\ngetLarchValue", encoding)
                self.assertTrue(any(f["line"] == 2 and f.get("reviewable") for f in hits))
                self.assertTrue(any(f["line"] == 3 and not f.get("reviewable") for f in hits))

    def test_overlapping_and_mixed_hits_cannot_hide_a_blocker(self):
        for term, text in [("ana", "ananAna"), ("larch", "overlarch larch")]:
            with self.subTest(text=text):
                hits = self.hits(term, text)
                self.assertTrue(any(f.get("reviewable") for f in hits))
                self.assertTrue(any(not f.get("reviewable") for f in hits))

    def test_nonalphabetic_terms_keep_the_previous_matching_rule(self):
        for term in ("z07", "a1", "1", "a1b2", "foo-bar", "dot.name", "foo_bar", "élan1", "猫1", "a+b"):
            for text in (term, "x" + term + "y", "é" + term + "é", "_" + term + "_", term.upper()):
                with self.subTest(term=term, text=text):
                    pattern = re.escape(term)
                    if len(term) <= 3 and term.isalnum():
                        pattern = r"(?<![A-Za-z0-9])" + pattern + r"(?![A-Za-z0-9])"
                    expected = bool(re.search(pattern, text, re.I))
                    hits = self.hits(term, text)
                    self.assertEqual(bool(hits), expected)
                    self.assertTrue(all(not f.get("reviewable") for f in hits))

    def test_every_downgrade_has_an_adjacent_unicode_letter(self):
        # Guard the privacy invariant across letter, identifier and punctuation contexts.
        for prefix in ("", "a", "A", "é", "猫", "_", "1", "-", "'", "\u0301"):
            for suffix in ("", "s", "S", "é", "犬", "_", "1", ".", "’", "\u0301"):
                text = prefix + "larch" + suffix
                hits = self.hits("larch", text)
                self.assertTrue(hits)
                for finding in hits:
                    if finding.get("reviewable"):
                        self.assertTrue(prefix.isalpha() or suffix.isalpha(), text)

    def test_unicode_ignorecase_filename_matches_are_still_redacted(self):
        # re.I also matches dotless i, which casefold alone does not map to i.
        scanner = rc.Scanner(["i"])
        scanner.file(b"", "tree", "mıx.txt")
        self.assertTrue(scanner.findings)
        self.assertTrue(all(f["path"].startswith("[path-") for f in scanner.findings))
        self.assertNotIn("mıx", json.dumps(scanner.findings, ensure_ascii=False))


class PrivacyIntegrationTests(unittest.TestCase):
    def setUp(self):
        # Reuse the existing fully synthetic, valid repository fixture.
        self.fixture = fixtures.AuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.denylist.write_text(json.dumps(["larch"]))

    def cli(self, *args):
        fixture = self.fixture
        result = subprocess.run([sys.executable, rc.__file__, str(fixture.repo),
                                 "--denylist", str(fixture.denylist),
                                 "--reports", str(fixture.root / "reports"), *args],
                                capture_output=True, text=True, timeout=60)
        self.assertNotIn("larch", (result.stdout + result.stderr).lower())
        locator = json.loads(result.stdout.splitlines()[0])["report"]
        report_path = fixture.root / "reports" / locator
        raw_json, markdown = report_path.read_text(), report_path.with_suffix(".md").read_text()
        self.assertNotIn("larch", (raw_json + markdown).lower())
        self.assertIn("## Reviewable private-term hits (nonblocking)", markdown)
        return result.returncode, json.loads(raw_json), markdown

    def test_reviewable_only_cli_and_export_remain_ready_and_redacted(self):
        fixture = self.fixture
        (fixture.repo / "overlarch.txt").write_text("ordinary\noverlarch\n")
        fixture.commit("Review overlarch")
        code, report, markdown = self.cli("--verify", "--scrub-plan", "--export", str(fixture.root / "export"))
        self.assertEqual(code, 0)
        for target in (report, report["export"]):
            self.assertTrue(target["ready"])
            self.assertEqual(target["counts"], {})
            self.assertEqual(target["findings"], [])
            self.assertGreater(target["reviewable_count"], 0)
            self.assertEqual(target["reviewable_count"], len(target["reviewable_findings"]))
            self.assertEqual(target["reviewed_count"], 0)
            self.assertTrue(all(f["path"].startswith("[path-") or f["scope"] == "metadata"
                                for f in target["reviewable_findings"]))
        self.assertEqual(report["scrub_plan"]["replace_or_remove"], [])
        self.assertTrue(any(f["line"] == 2 for f in report["reviewable_findings"]))
        self.assertTrue({"tree", "history", "metadata"} <= {f["scope"] for f in report["reviewable_findings"]})
        self.assertIn("[path-", markdown)

    def test_mixed_hits_remain_blocking_and_scrub_only_requires_blockers(self):
        fixture = self.fixture
        (fixture.repo / "data.txt").write_text("overlarch\nlarch\ngetLarchValue\n")
        fixture.commit("Fixture")
        code, report, _ = self.cli("--verify", "--scrub-plan", "--export", str(fixture.root / "export"))
        self.assertEqual(code, 1)
        for target in (report, report["export"]):
            self.assertFalse(target["ready"])
            self.assertGreater(target["counts"]["personal"], 0)
            self.assertTrue(any(f["line"] == 2 and f["kind"] == "denylist" for f in target["findings"]))
            self.assertTrue(any(f["line"] == 3 and f["kind"] == "denylist" for f in target["findings"]))
            self.assertTrue(any(f["line"] == 1 for f in target["reviewable_findings"]))
        self.assertTrue(all(f["line"] in {2, 3} for f in report["scrub_plan"]["replace_or_remove"]))

    def test_exact_denylist_approval_is_visible_and_limited_to_its_finding(self):
        fixture = self.fixture
        (fixture.repo / "public-data.csv").write_text("larch\n")
        (fixture.repo / "other-data.csv").write_text("larch\n")
        approval = {"scope": "tree", "kind": "denylist", "path": "public-data.csv",
                    "fingerprint": rc.fingerprint("larch"), "reason": "Verified this exact public IRS record."}
        manifest = {**fixture.manifest, "approvals": [approval]}
        report = rc.audit(fixture.repo, ["larch"], manifest, [], False, fixture.root / "reports", 10)
        matched = next(f for f in report["findings"] if f["path"] == "public-data.csv")
        unmatched = next(f for f in report["findings"] if f["path"] == "other-data.csv")
        self.assertTrue(matched["reviewed"])
        self.assertEqual(matched["review_source"], "owner approval")
        self.assertEqual(matched["review_status"], "accepted by owner approval")
        self.assertEqual(matched["reason"], approval["reason"])
        self.assertFalse(unmatched["reviewed"])
        self.assertNotIn("larch", json.dumps(report).lower())
        report_dir = fixture.root / "accepted-report"
        report_dir.mkdir()
        rc.write_reports(report_dir, report)
        markdown = (report_dir / "report.md").read_text()
        self.assertIn("accepted by owner approval", markdown)
        self.assertIn(approval["reason"], markdown)
        self.assertNotIn("larch", markdown.lower())

    def test_denylist_approval_requires_exact_fingerprint_and_reason(self):
        scanner = rc.Scanner(["larch"], approvals=[{"scope": "tree", "kind": "denylist",
            "path": "public-data.csv", "fingerprint": "0000000000000000", "reason": "Reviewed exact record."}])
        scanner.file(b"larch", "tree", "public-data.csv")
        self.assertFalse(scanner.findings[0]["reviewed"])
        self.assertEqual(scanner.matched_approvals, set())
        scanner = rc.Scanner(["larch"], approvals=[{"scope": "tree", "kind": "denylist",
            "path": "public-data.csv", "fingerprint": rc.fingerprint("larch"), "reason": "   "}])
        scanner.file(b"larch", "tree", "public-data.csv")
        self.assertFalse(scanner.findings[0]["reviewed"])

    def test_unmatched_denylist_approval_is_reported_stale(self):
        fixture = self.fixture
        approval = {"scope": "tree", "kind": "denylist", "path": "gone.csv",
                    "fingerprint": "0123456789abcdef", "reason": "Verified public data."}
        report = rc.audit(fixture.repo, ["larch"], {**fixture.manifest, "approvals": [approval]},
                          [], False, fixture.root / "reports", 10)
        self.assertEqual(report["stale_approvals"], [{key: approval[key] for key in
                         ("scope", "kind", "path", "fingerprint")}])
        report_dir = fixture.root / "stale-report"
        report_dir.mkdir()
        rc.write_reports(report_dir, report)
        self.assertIn("## Stale approvals", (report_dir / "report.md").read_text())

    def test_reviewable_hit_cannot_relax_other_gates_or_redaction(self):
        fixture = self.fixture
        (fixture.repo / "data.txt").write_text("overlarch\n")
        code, report, _ = self.cli()
        self.assertEqual(code, 2)
        self.assertGreater(report["reviewable_count"], 0)
        self.assertTrue(any(f["kind"] == "verification-not-run" for f in report["findings"]))
        scanner = rc.Scanner(["larch"])
        diagnostic = rc.venv_failure(b"Failure: overlarch", scanner)
        self.assertNotIn("larch", json.dumps(diagnostic))

    def test_deleted_history_and_commit_identity_components_still_block(self):
        fixture = self.fixture
        (fixture.repo / "larch.txt").write_text("larch\n")
        fixture.git("config", "user.name", "Larch")
        fixture.commit("getLarchValue")
        fixture.git("rm", "--", "larch.txt")
        fixture.git("config", "user.name", "Fixture")
        fixture.git("commit", "-q", "-m", "Remove")
        code, report, _ = self.cli("--verify")
        self.assertEqual(code, 1)
        self.assertTrue(any(f["scope"] == "history" and f["kind"] == "denylist" for f in report["findings"]))
        self.assertTrue(any(f["scope"] == "metadata" and f["kind"] == "denylist" for f in report["findings"]))

    def test_declared_project_quickstart_lines_remain_exact(self):
        root = Path(rc.__file__).parent
        manifest = json.loads((root / "release-check.json").read_text())
        for command in manifest["quickstart"]:
            line = (root / command["file"]).read_text().splitlines()[command["line"] - 1]
            self.assertEqual(shlex.split(line), command["argv"])


if __name__ == "__main__":
    unittest.main()

import json
import unittest

import release_check as rc
from licence_fixtures import genuine
from release_templates import TEMPLATES
import test_release_check as fixtures


def holder_text(identifier):
    return TEMPLATES[identifier][1].replace("{holder}", "2026 Testbed Contributors")


class RootLicenceTests(unittest.TestCase):
    def setUp(self):
        testbed = fixtures.AuditTests()
        testbed.setUp()
        self.addCleanup(testbed.doCleanups)
        self.repo, self.terms, self.manifest = testbed.repo, testbed.terms, testbed.manifest

    def audit(self, text, declared=None):
        (self.repo / "LICENSE").write_text(text)
        if declared is not None:
            (self.repo / "pyproject.toml").write_text('[project]\nname = "testbed"\nlicense = %s\n' % json.dumps(declared))
        scanner = rc.Scanner(self.terms)
        return rc.license_audit(self.repo, scanner, self.manifest), {f["kind"] for f in scanner.findings}

    def assert_root_licence(self, identifier, text):
        result, kinds = self.audit(text, identifier)
        self.assertEqual((result["status"], result["identifier"]), ("pass", identifier))
        self.assertNotIn("license-metadata-mismatch", kinds)
        _, kinds = self.audit(text, "MIT")
        self.assertIn("license-metadata-mismatch", kinds)
        result, kinds = self.audit(text.replace("without", "with"))
        self.assertEqual(result["status"], "blocked")
        self.assertIn("unrecognized-or-modified-license", kinds)
        if identifier != "Apache-2.0":
            unattributed = "".join(line for line in text.splitlines(True) if not line.startswith("Copyright"))
            self.assertEqual(self.audit(unattributed)[0]["status"], "blocked")

    def test_apache_2_0_root_licence_passes_with_matching_metadata(self):
        self.assert_root_licence("Apache-2.0", genuine("Apache-2.0"))

    def test_bsd_2_clause_root_licence_passes_with_matching_metadata(self):
        self.assert_root_licence("BSD-2-Clause", holder_text("BSD-2-Clause"))

    def test_bsd_3_clause_root_licence_passes_with_matching_metadata(self):
        self.assert_root_licence("BSD-3-Clause", holder_text("BSD-3-Clause"))
        self.assert_root_licence("BSD-3-Clause", genuine("BSD-3-Clause"))

    def test_isc_root_licence_passes_with_matching_metadata(self):
        self.assert_root_licence("ISC", holder_text("ISC"))

    def test_a_conflicting_heading_blocks_each_root_licence(self):
        for identifier, text in [("Apache-2.0", genuine("Apache-2.0")), ("BSD-2-Clause", holder_text("BSD-2-Clause")),
                                 ("BSD-3-Clause", holder_text("BSD-3-Clause")), ("ISC", holder_text("ISC"))]:
            for heading in ("LGPL-3.0-only", "MPL-2.0", "MIT"):
                with self.subTest(identifier=identifier, heading=heading):
                    result, kinds = self.audit(heading + "\n" + text)
                    self.assertEqual(result["status"], "blocked")
                    self.assertIn("unrecognized-or-modified-license", kinds)

    def test_two_different_root_licences_block(self):
        (self.repo / "COPYING").write_text(genuine("Apache-2.0"))
        result, kinds = self.audit(genuine("MIT"))
        self.assertEqual(result["status"], "blocked")
        self.assertIn("license-metadata-mismatch", kinds)


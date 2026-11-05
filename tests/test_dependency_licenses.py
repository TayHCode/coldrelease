"""Offline installed metadata fixtures; no real packages are installed."""
import hashlib
import io
import json
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

import release_check as rc


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.info = self.root / "fixture_name-1.0.dist-info"
        self.info.mkdir()
        self.package = {"name": "fixture_name", "version": "1.0", "expression": None,
                        "license": None, "classifiers": [], "license_files": []}

    def installed(self, expression=None, label=None, classifiers=(), text=None):
        headers = ["Metadata-Version: 2.4", "Name: fixture_name", "Version: 1.0"]
        if expression:
            headers.append("License-Expression: " + expression)
        if label:
            headers.append("License: " + label)
        headers.extend("Classifier: " + c for c in classifiers)
        (self.info / "METADATA").write_text("\n".join(headers) + "\n")
        records = [self.info.name + "/METADATA,,"]
        if text is not None:
            (self.info / "LICENSE").write_text(text)
            records.append(self.info.name + "/LICENSE,,")
        else:
            (self.info / "LICENSE").unlink(missing_ok=True)
        (self.info / "RECORD").write_text("\n".join(records) + "\n")
        # Discover only our synthetic installed distribution.
        script = "import sys\n" + rc.METADATA_SCRIPT.replace("m.distributions()", "m.distributions(path=[sys.argv[1]])")
        raw = subprocess.run([sys.executable, "-c", script, str(self.root)],
                             check=True, capture_output=True).stdout
        self.package = json.loads(raw)[0]
        return raw

    def audit(self, raw=None, approvals=(), evidence=None):
        scanner = rc.Scanner(["SyntheticPrivateTerm"], approvals=approvals)
        manifest = {"dependency_licenses": evidence or {}}
        result = rc.dependency_audit(raw or json.dumps([self.package]).encode(), self.root, scanner, manifest)
        return result, scanner.findings

    def test_permissive_identifiers_and_metadata_fields(self):
        for label in sorted(rc.COMPATIBLE):
            with self.subTest(label=label):
                self.assertEqual(self.audit(self.installed(expression=label))[0]["blocked"], 0)
                self.assertEqual(self.audit(self.installed(label=label))[0]["blocked"], 0)
        for label in ("MIT License", "Apache License, Version 2.0", "BSD License", "BSD 3-Clause License"):
            self.assertEqual(self.audit(self.installed(label=label))[0]["blocked"], 0)

    def test_full_mit_license_metadata_and_strong_label_conflict(self):
        text = Path(rc.__file__).with_name("LICENSE").read_text()
        self.assertEqual(self.audit(self.installed(label=text.splitlines()[0]))[0]["blocked"], 0)
        self.package["license"] = text
        self.package["licenses"] = [text]
        self.assertEqual(self.audit()[0]["blocked"], 0)
        self.assertEqual(self.audit(self.installed(expression="MIT", label="GPLv3"))[0]["blocked"], 1)
        self.assertEqual(self.audit(self.installed(label="Other/Proprietary License"))[0]["blocked"], 1)
        self.assertEqual(self.audit(self.installed(expression="LGPL-fake"))[0]["blocked"], 1)

    def test_classifiers_include_generic_bsd(self):
        for label in rc.CLASSIFIERS:
            with self.subTest(label=label):
                self.assertEqual(self.audit(self.installed(classifiers=["License :: OSI Approved :: " + label]))[0]["blocked"], 0)

    def test_gpl_agpl_spellings_in_every_metadata_source(self):
        for label in ("GPL", "GPLv2", "GPLv3", "GPL-3.0-only", "GPL-2.0+", "AGPL", "AGPLv3", "AGPL-3.0-or-later", "GNU General Public License", "GNU General Public License v3 (GPLv3)", "GNU Affero General Public License v3"):
            for source in ("expression", "label", "classifiers"):
                with self.subTest(label=label, source=source):
                    value = ["License :: OSI Approved :: " + label] if source == "classifiers" else label
                    result, findings = self.audit(self.installed(**{source: value}))
                    self.assertEqual(result["blocked"], 1)
                    self.assertEqual(findings[0]["kind"], "dependency-license-review")

    def test_weak_copyleft_is_accepted(self):
        for label in ("LGPL", "LGPLv2.1", "LGPL-3.0-or-later", "GNU Lesser General Public License v3 (LGPLv3)", "GNU Library General Public License", "GNU Library or Lesser General Public License (LGPL)", "GNU Lesser General Public License v2 or later (LGPLv2+)", "MPL-2.0", "Mozilla Public License 2.0 (MPL 2.0)", "EPL-1.0", "EPL-2.0", "Eclipse Public License 2.0"):
            with self.subTest(label=label):
                self.assertEqual(self.audit(self.installed(label=label))[0]["blocked"], 0)
                self.assertEqual(self.audit(self.installed(classifiers=["License :: OSI Approved :: " + label]))[0]["blocked"], 0)

    def test_unlabelled_file_acceptance_and_missing_file(self):
        result, findings = self.audit(self.installed(text=Path(rc.__file__).with_name("LICENSE").read_text()))
        self.assertEqual(findings, [])
        self.assertEqual(result["accepted_on_license_file"], ["@dependency/fixture_name"])
        self.assertEqual(self.audit(self.installed(label="UNKNOWN", text=Path(rc.__file__).with_name("LICENSE").read_text()))[0]["blocked"], 0)
        self.assertEqual(self.audit(self.installed(text=None))[0]["blocked"], 1)
        self.assertEqual(self.audit(self.installed(expression="MIT", text=None))[0]["blocked"], 0)
        self.package["expression"] = None
        self.package["expressions"] = []
        self.package["license_files"] = [{"path": "NOTICE", "hash": "f" * 64, "text": "A notice"}]
        self.assertEqual(self.audit()[0]["blocked"], 1)

    def test_package_path_is_not_mistaken_for_a_license_file(self):
        renamed = self.root / "license_fixture-1.0.dist-info"
        self.info.rename(renamed)
        self.info = renamed
        raw = self.installed(text=None)
        self.assertEqual(self.package["license_files"], [])
        self.assertEqual(self.audit(raw)[0]["blocked"], 1)
        (self.info / "terms.txt").write_text(Path(rc.__file__).with_name("LICENSE").read_text())
        with (self.info / "METADATA").open("a") as handle:
            handle.write("License-File: terms.txt\n")
        with (self.info / "RECORD").open("a") as handle:
            handle.write(self.info.name + "/terms.txt,,\n")
        script = "import sys\n" + rc.METADATA_SCRIPT.replace("m.distributions()", "m.distributions(path=[sys.argv[1]])")
        raw = subprocess.run([sys.executable, "-c", script, str(self.root)], check=True, capture_output=True).stdout
        self.assertEqual(self.audit(raw)[0]["blocked"], 0)

    def test_unlabelled_gpl_file_still_blocks(self):
        for text in ("GNU GENERAL PUBLIC LICENSE\nVersion 3", "GNU GENERAL\n  PUBLIC LICENSE\nVersion 3", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3", "SPDX-License-Identifier: GPL-2.0-only"):
            self.assertEqual(self.audit(self.installed(text=text))[0]["blocked"], 1)

    def test_shipped_weak_license_references_and_spdx_choices(self):
        cases = {
            "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3\nYou may convey a combined work. This incorporates the GNU General Public License by reference.": 1,
            "GNU GENERAL PUBLIC LICENSE\nThis is distinct from the GNU Lesser General Public License.": 1,
            "SPDX-License-Identifier: LGPL-3.0-or-later\nReferences the GPL.": 1,
            "SPDX-License-Identifier: MIT OR GPL-3.0-only": 0,
            "SPDX-License-Identifier: MIT AND GPL-3.0-only": 1,
            "SPDX-License-Identifier: GPL-3.0-only WITH Unknown-exception": 1,
            "SPDX-License-Identifier: MIT\nGNU GENERAL PUBLIC LICENSE": 1,
            "SPDX-License-Identifier: GPL-3.0-only OR MIT\nGNU GENERAL PUBLIC LICENSE": 1,
            "SPDX-License-Identifier: LicenseRef-Unknown": 1,
            "SPDX-License-Identifier: MIT\nSPDX-License-Identifier: AGPL-3.0-only": 1}
        for text, blocked in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.audit(self.installed(text=text))[0]["blocked"], blocked)

    def test_unknown_licence_needs_review(self):
        self.assertEqual(self.audit(self.installed(expression="LicenseRef-Unknown"))[0]["blocked"], 1)
        self.assertEqual(self.audit(self.installed(label="Unclassified terms"))[0]["blocked"], 1)

    def test_expressions_precedence_parentheses_and_unknowns(self):
        cases = {"MIT OR GPL-3.0-only": 0, "GPL-3.0-only OR MIT": 0,
                 "MIT AND GPL-3.0-only": 1, "GPLv3 OR AGPL-3.0-or-later": 1,
                 "MIT AND Apache-2.0": 0, "LGPL-3.0-only AND MPL-2.0": 0,
                 "MIT OR LicenseRef-Unknown": 0, "MIT AND LicenseRef-Unknown": 1,
                 "MIT OR GPLv3 AND AGPLv3": 0, "(MIT OR GPLv3) AND AGPLv3": 1,
                 "(GPLv3 AND MIT) OR (Apache-2.0 AND BSD)": 0,
                 "GPLv3 WITH Unknown-exception": 1, "MIT OR": 1, "(MIT": 1, "MIT AND GPL-3.0-or-later": 1,
                 "LGPL-2.1-or-later AND MIT": 0, "GPL-3.0-or-later OR MIT": 0,
                 "LGPL-2.1-or-later AND GPL-3.0-or-later": 1}
        for label, blocked in cases.items():
            with self.subTest(label=label):
                self.assertEqual(self.audit(self.installed(expression=label))[0]["blocked"], blocked)

    def test_strong_classifier_cannot_be_hidden(self):
        classifier = ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"]
        self.assertEqual(self.audit(self.installed(expression="MIT", classifiers=classifier))[0]["blocked"], 1)
        self.assertEqual(self.audit(self.installed(expression="GPLv3 OR MIT", classifiers=classifier))[0]["blocked"], 1)
        self.assertEqual(self.audit(self.installed(expression="GPLv3 OR LGPL-3.0-only", classifiers=classifier))[0]["blocked"], 1)

    def test_existing_evidence_and_normalized_package_keys(self):
        raw = self.installed(expression="LicenseRef-Ambiguous", text="Synthetic licence evidence")
        evidence = {"version": "1.0", "spdx": "MIT", "sha256": hashlib.sha256(b"Synthetic licence evidence").hexdigest()}
        for key in ("fixture_name", "fixture-name"):
            self.assertEqual(self.audit(raw, evidence={key: evidence})[0]["blocked"], 0)
        for field in ("version", "sha256"):
            self.assertEqual(self.audit(raw, evidence={"fixture-name": {**evidence, field: "stale"}})[0]["blocked"], 1)
        self.assertEqual(self.audit(self.installed(expression="GPLv3"), evidence={"fixture-name": evidence})[0]["blocked"], 1)
        self.assertEqual(self.audit(self.installed(classifiers=["License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)"]), evidence={"fixture-name": evidence})[0]["blocked"], 1)

    def test_review_is_visible_and_requires_reason(self):
        raw = self.installed(expression="GPLv3")
        hit = self.audit(raw)[1][0]
        self.assertEqual(self.audit(raw, approvals=[hit])[0]["blocked"], 1)
        for reason in ("", "   ", None, 12):
            self.assertFalse(self.audit(raw, approvals=[{**hit, "reason": reason}])[1][0]["reviewed"])
        result, findings = self.audit(raw, approvals=[{**hit, "reason": "Reviewed obligations for this exact distribution."}])
        self.assertEqual(result["blocked"], 0)
        self.assertTrue(findings[0]["reviewed"])
        self.assertEqual(findings[0]["fingerprint"], hit["fingerprint"])
        self.assertNotIn("text", findings[0])

    def test_review_is_bound_to_supplied_dependency_evidence(self):
        raw = self.installed(expression="LicenseRef-Ambiguous", text="Synthetic licence evidence")
        entry = {"version": "1.0", "spdx": "GPLv3", "sha256": self.package["license_files"][0]["hash"]}
        evidence = {"fixture-name": entry}
        hit = self.audit(raw, evidence=evidence)[1][0]
        approval = {**hit, "reason": "Accepted exact evidence."}
        self.assertTrue(self.audit(raw, approvals=[approval], evidence=evidence)[1][0]["reviewed"])
        changed = {"fixture-name": {**entry, "spdx": "AGPLv3"}}
        self.assertFalse(self.audit(raw, approvals=[approval], evidence=changed)[1][0]["reviewed"])
        self.assertFalse(self.audit(raw, approvals=[approval])[1][0]["reviewed"])

    def test_stale_reviews_bind_package_version_metadata_and_file(self):
        self.installed(expression="GPLv3")
        original = json.loads(json.dumps(self.package))
        approval = {**self.audit()[1][0], "reason": "Reviewed."}
        for field, value in (("name", "different"), ("version", "2.0"), ("expression", "AGPLv3"), ("license", "GPLv2"), ("classifiers", ["License :: GPLv2"]), ("license_files", [{"path": "LICENSE", "hash": "a" * 64}])):
            with self.subTest(field=field):
                self.package = {**original, field: value}
                self.assertFalse(self.audit(approvals=[approval])[1][0]["reviewed"])
        self.package = original
        for field in ("scope", "kind", "path", "fingerprint"):
            self.assertFalse(self.audit(approvals=[{**approval, field: "different"}])[1][0]["reviewed"])

    def test_project_manifest_quickstart_lines_match_readme(self):
        root = Path(rc.__file__).parent
        manifest = rc.manifest_for(root, None)
        for item in manifest["quickstart"]:
            line = (root / item["file"]).read_text().splitlines()[item["line"] - 1]
            self.assertEqual(shlex.split(line), item["argv"])
        self.assertIn(["coldrelease", "--requirements"], [i["argv"] for i in manifest["quickstart"]])

    def test_requirements_command_without_repo_or_denylist(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(rc.main(["--requirements"]), 0)
        self.assertEqual(out.getvalue(), rc.requirements_text())
        text = out.getvalue()
        self.assertIn("Denylist hits require exact owner approval; secrets cannot be waived.", text)
        self.assertNotIn("denylist/secrets cannot be waived", text)
        for value in (*rc.ROOT_LICENSE_FILES, *rc.REQUIRED_DOCUMENTS, *rc.README_HEADINGS, *rc.ISSUE_TEMPLATE_GLOBS, rc.TEST_GLOB, 'GPL-3.0.txt', 'licenses/licences', *rc.MANIFEST_KEYS, *rc.CHECK_ROLES):
            self.assertIn(value, text)
        example = json.JSONDecoder().raw_decode(text[text.index('{'):])[0]
        (self.root / "release-check.json").write_text(json.dumps(example))
        self.assertEqual(rc.manifest_for(self.root, None), example)


if __name__ == "__main__":
    unittest.main()

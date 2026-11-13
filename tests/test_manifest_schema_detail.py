from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest

import release_check as rc
import test_release_check as fixtures


class ManifestSchemaDetailTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)

    def manifest_file(self, obj):
        path = self.testbed.root / "other-manifest.json"
        path.write_text(json.dumps(obj))
        return path

    def run_main(self, command, obj):
        fx = self.testbed
        args = [str(fx.repo), "--denylist", str(fx.denylist), "--manifest", str(self.manifest_file(obj))]
        if command:
            args = [command, *args]
        else:
            args += ["--reports", str(fx.root / "reports")]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rc.main(args)
        return code, out.getvalue(), err.getvalue()

    def assert_detail(self, obj, *needles):
        code, out, err = self.run_main(None, obj)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        error = json.loads(err)
        self.assertEqual((error["outcome"], error["ready"], error["error"]), ("INCOMPLETE", False, "manifest-schema"))
        for needle in needles:
            self.assertIn(needle, error["detail"])
        code, out, err = self.run_main("plan", obj)
        self.assertEqual(code, 2)
        result = json.loads(out)
        self.assertEqual(result["reasons"], ["manifest-schema"])
        self.assertEqual(result["detail"], error["detail"])
        return error["detail"]

    def test_unknown_top_level_keys_are_named_with_the_allowed_keys(self):
        detail = self.assert_detail({"schema_version": 1, "name": "skills", "license": "MIT", "skills": []},
                                    "schema_version", "name", "skills", *rc.MANIFEST_KEYS)
        self.assertNotIn("MIT", detail)

    def test_non_object_manifest_is_described(self):
        self.assert_detail(["not", "an", "object"], "object")

    def test_list_key_with_wrong_type_is_named(self):
        for key in ("exclude", "approvals", "quickstart", "checks"):
            with self.subTest(key=key):
                self.assert_detail({key: "private-value"}, key, "list")

    def test_non_object_items_name_the_list_key_without_the_value(self):
        for key in ("approvals", "quickstart", "checks"):
            with self.subTest(key=key):
                detail = self.assert_detail({key: ["private-value"]}, key, "object")
                self.assertNotIn("private-value", detail)

    def test_dependency_licenses_must_be_an_object(self):
        self.assert_detail({"dependency_licenses": ["private-value"]}, "dependency_licenses", "object")

    def test_bad_verify_tools_are_named(self):
        cases = {
            "not-a-list": "tool",
            "too-many": [f"tool{i}" for i in range(9)],
            "bad-name": ["bad name"],
            "non-string": [1],
            "duplicate": ["tool", "tool"],
        }
        for label, value in cases.items():
            with self.subTest(label=label):
                detail = self.assert_detail({"verify_tools": value}, "verify_tools")
                self.assertNotIn("bad name", detail)


if __name__ == "__main__":
    unittest.main()

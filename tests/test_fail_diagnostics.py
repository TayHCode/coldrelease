from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures
import test_npm_source_review as npm_fixtures


class FailDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def cli(self, command=None, *extra):
        fx = self.fx
        args = [str(fx.repo), '--denylist', str(fx.denylist)]
        args = [command, *args, '--run', 'diagnostics'] if command else [*args, '--reports', str(fx.root / 'reports')]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rc.main([*args, *extra])
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        return code, json.loads(out.getvalue()), err.getvalue()

    def add_npm(self):
        npm = npm_fixtures.NpmSourceReviewTests()
        npm.setUp()
        self.addCleanup(npm.doCleanups)
        for name in ('package.json', 'package-lock.json'):
            (self.fx.repo / name).write_bytes((npm.repo / name).read_bytes())
        self.fx.commit('Add source dependencies')

    def test_unapproved_npm_review_explains_approval_and_preserves_summary(self):
        self.add_npm()
        code, summary, err = self.cli(None, '--verify')
        self.assertEqual(code, 1)
        self.assertEqual({k: v for k, v in summary.items() if k != 'report'},
                         {'outcome': 'FAIL', 'ready': False, 'counts': {'license': 1}})
        report = json.loads((self.fx.root / 'reports' / summary['report']).read_text())
        finding = next(f for f in report['findings'] if f['kind'] == 'npm-source-declarations-review')
        self.assertIn('license: npm source review for package.json is not approved; add an approval with fingerprint ' + finding['fingerprint'] + ' (see README)', err)

    def test_private_term_names_path_and_fix_without_matched_text(self):
        (self.fx.repo / 'notes.txt').write_text('HiddenPerson')
        self.fx.commit('Add synthetic finding')
        code, summary, err = self.cli(None, '--verify')
        self.assertEqual(code, 1)
        self.assertEqual(summary['outcome'], 'FAIL')
        self.assertEqual(summary['counts'], {'personal': 2})
        self.assertIn('personal: denylist in notes.txt;', err)
        self.assertIn('remove or replace', err)
        self.assertNotIn('HiddenPerson', err)
        self.assertEqual(len(err.splitlines()), 2)

    def test_pass_has_no_diagnostics(self):
        code, summary, err = self.cli(None, '--verify')
        self.assertEqual((code, summary['outcome'], summary['ready'], summary['counts'], err),
                         (0, 'PASS', True, {}, ''))

    def test_approved_findings_are_silent_and_control_characters_are_escaped(self):
        scanner = rc.Scanner(['HiddenPerson'])
        scanner.add('tree', 'personal', 'denylist', 'notes\n\x1b.txt', value='HiddenPerson')
        approved = scanner.add('tree', 'license', 'npm-source-declarations-review', 'approved.json')
        approved['reviewed'] = True
        report = {'outcome': 'FAIL', 'findings': scanner.findings}
        err = io.StringIO()
        with redirect_stderr(err):
            rc.print_fail_findings(report)
        self.assertEqual(len(err.getvalue().splitlines()), 1)
        self.assertIn(r'notes[newline]\u001b.txt', err.getvalue())
        self.assertNotIn('approved.json', err.getvalue())
        self.assertNotIn('HiddenPerson', err.getvalue())

    def test_workflow_preflight_explains_npm_review(self):
        self.add_npm()
        code, summary, err = self.cli('preflight')
        self.assertEqual((code, summary['outcome']), (1, 'FAIL'))
        self.assertIn('license: npm source review for package.json is not approved; add an approval with fingerprint ', err)

    def test_workflow_audit_verdicts_explain_blockers(self):
        self.assertEqual(self.cli('plan')[0], 0)
        (self.fx.repo / 'notes.txt').write_text('HiddenPerson')
        self.fx.commit('Add synthetic finding')
        # Include the newly tracked file in the already prepared export allowlist.
        allowlist = self.fx.repo / '.coldrelease/runs/diagnostics/public-export.txt'
        allowlist.write_text(allowlist.read_text() + 'notes.txt\n')
        for command in ('check', 'export'):
            with self.subTest(command=command):
                code, summary, err = self.cli(command, '--verify')
                self.assertEqual((code, summary['outcome']), (1, 'FAIL'))
                self.assertIn('personal: denylist in notes.txt;', err)
                self.assertIn('remove or replace', err)

    def test_workflow_external_scanner_failure_has_a_safe_action(self):
        self.assertEqual(self.cli('plan', '--scanner', 'gitleaks')[0], 0)
        with patch.object(workflow, 'scan_export', return_value={'name': 'gitleaks', 'outcome': 'FAIL'}):
            code, summary, err = self.cli('export', '--verify')
        self.assertEqual((code, summary['outcome']), (1, 'FAIL'))
        self.assertEqual(summary['scanners'], [{'name': 'gitleaks', 'outcome': 'FAIL'}])
        self.assertIn('secrets: gitleaks found blockers in @export; remove secrets from the tree and history', err)


if __name__ == '__main__':
    unittest.main()

import unittest

import release_check as rc


def outcome(path, raw, approvals=()):
    scanner = rc.Scanner([], approvals=list(approvals))
    scanner.file(raw, 'tree', path)
    report = {'findings': scanner.findings, 'verification': {'status': 'pass'},
              'license': {'status': 'pass', 'dependencies': 'pass'}, 'stats': {'tree_files': 1, 'history_commits': 1}}
    return rc.outcome(report), [f for f in scanner.findings if f['category'] == 'deployment-config']


WORKFLOW_SAFE = b"""on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
      LOG_LEVEL: debug
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
          token: ${{ secrets.CHECKOUT_TOKEN }}
      - run: make deploy
        env:
          DB_PASSWORD: "${{ secrets.DB_PASSWORD }}"
"""

FAILING = {
    'state': ('infra/terraform.tfstate', b'{}\n'),
    'state-backup': ('terraform.tfstate.backup', b'{}\n'),
    'tfvars': ('prod.tfvars', b'region = "x"\n'),
    'kubeconfig': ('deploy/kubeconfig', b'apiVersion: v1\n'),
    'kube-config': ('ops/.kube/config', b'apiVersion: v1\n'),
    'npmrc': ('.npmrc', b'//registry.npmjs.org/:_authToken=abc123\n'),
    'pypirc': ('.pypirc', b'[pypi]\nusername = __token__\npassword = pypi-x\n'),
    'docker-config': ('.docker/config.json', b'{"auths": {"registry.example": {"auth": "abc123"}}}\n'),
    'k8s-secret-data': ('k8s/secret.yaml', b'apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  password: eA==\n'),
    'k8s-secret-string': ('k8s/all.yml', b'kind: ConfigMap\n---\nkind: Secret\nstringData:\n  token: hunter2\n'),
    'workflow-env': ('.github/workflows/ci.yml', WORKFLOW_SAFE.replace(b'"${{ secrets.DB_PASSWORD }}"', b'hunter2')),
    'workflow-with': ('.github/workflows/ci.yaml', WORKFLOW_SAFE.replace(b'${{ secrets.CHECKOUT_TOKEN }}', b'abc123')),
    'dockerfile-env': ('Dockerfile', b'FROM scratch\nENV API_KEY=abc123 MODE=prod\n'),
    'dockerfile-env-legacy': ('docker/app.Dockerfile', b'FROM scratch\nENV DB_PASSWORD hunter2\n'),
    'dockerfile-arg': ('Dockerfile.prod', b'FROM scratch\nARG NPM_TOKEN=abc123\n'),
    'compose-map': ('docker-compose.yml', b'services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: hunter2\n'),
    'workflow-quoted-boolean': ('.github/workflows/ci.yml', WORKFLOW_SAFE.replace(b'"${{ secrets.DB_PASSWORD }}"', b'"true"')),
    'workflow-dollar-literal': ('.github/workflows/ci.yml', WORKFLOW_SAFE.replace(b'"${{ secrets.DB_PASSWORD }}"', b'abc$def')),
    'workflow-inline-env': ('.github/workflows/ci.yml', WORKFLOW_SAFE.replace(b'LOG_LEVEL: debug', b'LOG_LEVEL: debug\n    container:\n      env: {MODE: x, TOKEN: abc123}')),
    'dockerfile-continuation': ('Dockerfile', b'FROM scratch\nENV MODE=prod \\\n    TOKEN=abc123\n'),
    'k8s-secret-in-list': ('k8s/list.yaml', b'kind: List\nitems:\n  - apiVersion: v1\n    kind: Secret\n    data:\n      token: eA==\n'),
    'docker-config-second-auth': ('.docker/config.json', b'{"auths": {"a": {"auth": "${A}"}, "b": {"auth": "abc123"}}}\n'),
    'workflow-mixed-expression': ('.github/workflows/ci.yml', WORKFLOW_SAFE.replace(b'"${{ secrets.DB_PASSWORD }}"', b'abc-${{ github.run_id }}')),
    'workflow-block-scalar': ('.github/workflows/ci.yml', WORKFLOW_SAFE.replace(b'"${{ secrets.DB_PASSWORD }}"', b'|\n            abc123')),
    'k8s-secret-flow': ('k8s/flow.yaml', b'{kind: Secret, data: {token: eA==}}\n'),
    'npmrc-boolean-text': ('.npmrc', b'//registry.npmjs.org/:_authToken=true\n'),
    'dockerfile-boolean-text': ('Dockerfile', b'FROM scratch\nENV API_KEY=true\n'),
    'compose-literal-default': ('docker-compose.yml', b'services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${DB_PASS:-hunter2}\n'),
    'k8s-empty-data-then-string-data': ('k8s/secret.yaml', b'kind: Secret\ndata: {}\nstringData:\n  token: hunter2\n'),
    'workflow-quoted-hash': ('.github/workflows/ci.yml', WORKFLOW_SAFE.replace(b'"${{ secrets.DB_PASSWORD }}"', b'" # abc"')),
    'k8s-secret-flow-multiline': ('k8s/flow.yaml', b'{kind: Secret,\n data: {token: eA==}}\n'),
    'compose-list': ('compose.prod.yaml', b'services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD=hunter2\n'),
}

PASSING = {
    'workflow-secrets-only': ('.github/workflows/ci.yml', WORKFLOW_SAFE),
    'npmrc-env-reference': ('.npmrc', b'//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nsave-exact=true\n'),
    'pypirc-no-password': ('.pypirc', b'[pypi]\nusername = __token__\n'),
    'docker-cred-helper': ('.docker/config.json', b'{"credsStore": "desktop"}\n'),
    'k8s-configmap': ('k8s/config.yaml', b'kind: ConfigMap\ndata:\n  mode: prod\n'),
    'k8s-secret-without-data': ('k8s/secret.yaml', b'kind: Secret\nmetadata:\n  name: app\ntype: Opaque\n'),
    'dockerfile-arg-without-default': ('Dockerfile', b'FROM scratch\nARG NPM_TOKEN\nENV SERVICE_API_KEY=${SERVICE_API_KEY}\n'),
    'compose-reference': ('docker-compose.yml', b'services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n'),
    'k8s-list-empty-secret': ('k8s/list.yaml', b'kind: List\nitems:\n  - kind: Secret\n    metadata:\n      name: app\n  - kind: ConfigMap\n    data:\n      mode: prod\n'),
    'k8s-secret-data-comment-only': ('k8s/secret.yaml', b'kind: Secret\ndata:\n  # filled by the operator\ntype: Opaque\n'),
    'k8s-flow-list': ('k8s/list.yaml', b'{kind: List, items: [{kind: Secret}, {kind: ConfigMap, data: {mode: prod}}]}\n'),
    'workflow-inline-expression-commas': ('.github/workflows/ci.yml', WORKFLOW_SAFE.replace(
        b'LOG_LEVEL: debug', b'LOG_LEVEL: debug\n    container:\n      env: {TOKEN: "${{ format(\'{0},{1}\', secrets.A, secrets.B) }}"}')),
    'tf-source': ('main.tf', b'variable "region" {}\n'),
}


class DeploymentConfigTests(unittest.TestCase):
    def test_each_deployment_secret_fails(self):
        for name, (path, raw) in FAILING.items():
            with self.subTest(name):
                result, findings = outcome(path, raw)
                self.assertEqual(result['outcome'], 'FAIL', findings)
                self.assertTrue(findings)

    def test_clean_deployment_files_pass(self):
        for name, (path, raw) in PASSING.items():
            with self.subTest(name):
                result, findings = outcome(path, raw)
                self.assertEqual(findings, [])
                self.assertEqual(result['outcome'], 'PASS', result)

    def test_self_hosted_runner_needs_manual_review(self):
        for runs_on in (b'self-hosted', b'[self-hosted, linux]', b'\n      - self-hosted\n      - gpu'):
            with self.subTest(runs_on):
                raw = WORKFLOW_SAFE.replace(b'ubuntu-latest', runs_on)
                result, findings = outcome('.github/workflows/ci.yml', raw)
                self.assertEqual(result['outcome'], 'INCOMPLETE')
                line = 5 if runs_on.startswith(b'\n') else 4
                self.assertEqual([(f['kind'], f['line']) for f in findings], [('manual-review', line)])
                approval = {key: findings[0][key] for key in ('scope', 'kind', 'path', 'fingerprint')}
                self.assertEqual(outcome('.github/workflows/ci.yml', raw, [approval])[0]['outcome'], 'PASS')

    def test_literal_secret_findings_hide_the_value(self):
        path, raw = FAILING['workflow-env']
        _, findings = outcome(path, raw)
        self.assertEqual([(f['kind'], f['line']) for f in findings], [('literal-secret', 15)])
        self.assertNotIn('hunter2', repr(findings))

    def test_history_is_checked_too(self):
        scanner = rc.Scanner([])
        scanner.file(b'{}', 'history', 'terraform.tfstate', 'a' * 40)
        self.assertEqual([(f['scope'], f['kind']) for f in scanner.findings if f['category'] == 'deployment-config'],
                         [('history', 'deployment-state')])


if __name__ == '__main__':
    unittest.main()

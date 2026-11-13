from contextlib import redirect_stderr, redirect_stdout
import base64
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import threading
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
from tests import test_release_workflow as flows

SECRET = "synthetic-" + "credential-value"


class PrivateGitHttp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.serve()

    def do_POST(self):
        self.serve()

    def serve(self):
        self.server.seen_headers.append(dict(self.headers))
        if self.headers.get("Authorization") != self.server.expected_authorization:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="private"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path, _, query = self.path.partition("?")
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        environment = {"PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                       "GIT_PROJECT_ROOT": str(self.server.project_root), "GIT_HTTP_EXPORT_ALL": "1",
                       "REQUEST_METHOD": self.command, "PATH_INFO": path, "QUERY_STRING": query,
                       "CONTENT_TYPE": self.headers.get("Content-Type", ""), "CONTENT_LENGTH": str(len(body)),
                       "REMOTE_USER": "synthetic", "REMOTE_ADDR": '127.' '0.0.1'}
        for header, name in (("Content-Encoding", "HTTP_CONTENT_ENCODING"), ("Git-Protocol", "HTTP_GIT_PROTOCOL")):
            if self.headers.get(header):
                environment[name] = self.headers[header]
        output = subprocess.run(["git", "http-backend"], input=body, capture_output=True, env=environment).stdout
        head, _, payload = output.partition(b"\r\n\r\n")
        headers = [line.split(":", 1) for line in head.decode().splitlines() if ":" in line]
        status = next((int(value.split()[0]) for name, value in headers if name.lower() == "status"), 200)
        self.send_response(status)
        for name, value in headers:
            if name.lower() != "status":
                self.send_header(name, value.strip())
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class PrivateHttpTargetTests(unittest.TestCase):
    def setUp(self):
        self.flow = flows.WorkflowTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.root = self.flow.root
        self.project_root = self.root / "served"
        self.project_root.mkdir()
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.project_root / "private.git")], check=True, capture_output=True)
        server = http.server.ThreadingHTTPServer(('127.' '0.0.1', 0), PrivateGitHttp)
        server.project_root = self.project_root
        server.seen_headers = []
        server.expected_authorization = "Basic " + base64.b64encode(("synthetic:" + SECRET).encode()).decode()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.server = server
        self.origin = 'http://127.' '0.0.1:%d' % server.server_address[1]
        self.target = self.origin + "/private.git"
        self.home = self.root / "home"
        (self.home / ".coldlocker").mkdir(parents=True)
        (self.home / ".coldlocker" / "release-denylist.sha256").write_text(self.flow.reference.read_text())
        self.log = self.root / "helper.log"
        helper = self.root / "logging-helper"
        helper.write_text("#!/bin/sh\n"
                          "input=$(cat)\n"
                          "printf '%s %s %s\\n' \"$1\" \"$(printf '%s\\n' \"$input\" | grep '^protocol=')\" "
                          "\"$(printf '%s\\n' \"$input\" | grep '^host=')\" >> " + str(self.log) + "\n"
                          "[ \"$1\" = get ] && printf 'username=synthetic\\npassword=%s\\n' " + SECRET + "\n"
                          "exit 0\n")
        helper.chmod(0o700)
        self.write_gitconfig("[credential]\n\thelper =\n"
                                 "[credential \"" + self.origin + "\"]\n\thelper =\n\thelper = " + str(helper) + "\n"
                                 "[http]\n\textraHeader = X-Global-Config: leaked\n")
        environment = patch.dict(os.environ, {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config"),
                                              "GIT_CONFIG_GLOBAL": str(self.home / ".gitconfig")})
        environment.start()
        self.addCleanup(environment.stop)

    def write_gitconfig(self, text):
        (self.home / ".gitconfig").write_text(text)

    def helper_calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def assert_only_target_was_asked(self):
        calls = self.helper_calls()
        self.assertIn("get protocol=http host=" + self.origin.removeprefix("http://"), calls)
        self.assertEqual({call.split(" ", 1)[1] for call in calls},
                         {"protocol=http host=" + self.origin.removeprefix("http://")})
        self.assertFalse([h for h in self.server.seen_headers if "X-Global-Config" in h])

    def assert_secret_not_kept(self, *texts):
        for text in texts:
            self.assertNotIn(SECRET, text)
        for path in self.root.rglob("*"):
            if path.is_file() and path.name != "logging-helper" and ".git" not in path.relative_to(self.root).parts:
                self.assertNotIn(SECRET.encode(), path.read_bytes(), path)

    def main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = rc.main(argv)
        except SystemExit as exit:
            self.fail("usage error %s: %s" % (exit.code, err.getvalue()))
        return code, out.getvalue(), err.getvalue()

    def workflow_cli(self, command, *extra):
        code, out, err = self.main([command, str(self.flow.repo), "--denylist", str(self.flow.testbed.denylist),
                                    "--run", "first", *extra])
        return code, json.loads(out), err

    def final_gate(self, clone, *extra):
        with patch.object(rc, "verify", side_effect=flows.verified):
            return self.main([str(clone), "--denylist", str(self.flow.testbed.denylist), "--reports", str(self.root / "final"),
                              "--verify", "--published-target", self.target, "refs/heads/main", *extra])

    def push(self):
        subprocess.run(workflow.push_command(self.flow.run, workflow.read_json(self.flow.run / "approval.json")),
                       check=True, capture_output=True)
        self.log.unlink(missing_ok=True)
        self.server.seen_headers.clear()

    def flags(self):
        return [*self.flow.target_flags(self.target), "--use-git-credentials"]

    def assert_default_never_asks_the_helper(self):
        subprocess.run(["git", "ls-remote", self.target], capture_output=True)
        self.assertIn("get protocol=http host=" + self.origin.removeprefix("http://"), self.helper_calls())
        self.log.unlink()
        self.server.seen_headers.clear()
        attempt = self.flow.export()
        code, result, err = self.workflow_cli("approve", *self.flow.target_flags(self.target))
        self.assertEqual((code, result["reasons"]), (2, ["git-read-failed"]), result)
        clone = self.root / "unpublished-clone"
        rc.git(self.root, "clone", "-q", str(self.flow.repo), str(clone))
        code, out, err = self.final_gate(clone)
        self.assertEqual((code, json.loads(err)["error"]), (2, "published-ref-unavailable"), out + err)
        self.assertEqual(self.helper_calls(), [])
        self.assertFalse([h for h in self.server.seen_headers if "X-Global-Config" in h])
        return attempt

    def test_only_the_opt_in_approves_publishes_and_gates_a_private_http_target(self):
        attempt = self.assert_default_never_asks_the_helper()
        flags = self.flags()
        code, approved, err = self.workflow_cli("approve", *flags)
        self.assertEqual((code, approved["outcome"]), (0, "PASS"), approved)
        self.assertIsNone(approved["expected_public_head"])
        self.assert_only_target_was_asked()
        self.push()
        code, published, publish_err = self.workflow_cli("publish", *flags)
        self.assertEqual((code, published["outcome"]), (0, "PASS"), published)
        export_head = workflow.read_json(attempt / "receipt.json")["export_head"]
        served = self.project_root / "private.git"
        self.assertEqual(rc.git(served, "rev-parse", "refs/heads/main").decode().strip(), export_head)
        clone = self.root / "published-clone"
        rc.git(self.root, "clone", "-q", "--no-local", str(served), str(clone))
        code, out, gate_err = self.final_gate(clone, "--use-git-credentials")
        self.assertEqual(code, 0, out + gate_err)
        summary = json.loads(out)
        self.assertEqual((summary["outcome"], summary["published_target"]["head"]), ("PASS", export_head))
        self.assert_only_target_was_asked()
        self.assert_secret_not_kept(json.dumps(approved), err, json.dumps(published), publish_err, out, gate_err)

    def test_ship_publishes_and_gates_a_private_http_target_with_the_opt_in(self):
        attempt = self.flow.export()
        flags = self.flags()
        code, approved, err = self.workflow_cli("approve", *flags)
        self.assertEqual((code, approved["outcome"]), (0, "PASS"), approved)
        self.push()
        argv = ["ship", str(self.flow.repo), "--denylist", str(self.flow.testbed.denylist), "--run", "first", *flags]
        with patch.object(rc, "verify", side_effect=flows.verified):
            code, out, ship_err = self.main(argv)
        result = json.loads(out)
        self.assertEqual((code, result["outcome"], result["final_gate"]["outcome"]), (0, "PASS", "PASS"), out + ship_err)
        export_head = workflow.read_json(attempt / "receipt.json")["export_head"]
        self.assertEqual(rc.git(self.project_root / "private.git", "rev-parse", "refs/heads/main").decode().strip(), export_head)
        self.assert_only_target_was_asked()
        self.assert_secret_not_kept(json.dumps(approved), err, out, ship_err)

    def test_confirm_public_waits_for_the_flip_then_records_public_verified(self):
        self.flow.export()
        flags = self.flags()
        self.assertEqual(self.workflow_cli("approve", *flags)[0], 0)
        self.push()
        argv = ["ship", str(self.flow.repo), "--denylist", str(self.flow.testbed.denylist), "--run", "first", *flags]
        with patch.object(rc, "verify", side_effect=flows.verified):
            code, out, err = self.main(argv)
        self.assertEqual(code, 0, out + err)
        with patch.object(rc, "verify", side_effect=flows.verified):
            code, private, err = self.workflow_cli("confirm-public")
            self.assertEqual((code, private["reasons"]), (2, ["published-clone-failed"]), err)
            self.server.expected_authorization = None
            code, public, err = self.workflow_cli("confirm-public")
        self.assertEqual((code, public["outcome"], public["state"]), (0, "PASS", "public-verified"), err)
        self.assertEqual(workflow.read_json(self.flow.run / "public-verified.json")["published_head"], public["published_head"])
        self.assert_secret_not_kept(json.dumps(private), json.dumps(public), err)

    def test_opt_in_reads_helpers_from_included_global_config(self):
        included = self.home / "included.gitconfig"
        included.write_text((self.home / ".gitconfig").read_text())
        self.write_gitconfig("[include]\n\tpath = " + str(included) + "\n")
        clone = self.root / "published-clone"
        rc.git(self.root, "clone", "-q", str(self.flow.repo), str(clone))
        code, out, err = self.final_gate(clone, "--use-git-credentials")
        self.assertEqual((code, json.loads(err)["error"]), (2, "published-ref-missing"), out + err)
        self.assert_only_target_was_asked()

    def test_opt_in_without_a_global_helper_is_incomplete(self):
        self.write_gitconfig("[http]\n\textraHeader = X-Global-Config: leaked\n")
        self.flow.export()
        code, result, err = self.workflow_cli("approve", *self.flags())
        self.assertEqual((code, result["reasons"]), (2, ["git-credentials-missing"]), result)
        clone = self.root / "published-clone"
        rc.git(self.root, "clone", "-q", str(self.flow.repo), str(clone))
        code, out, err = self.final_gate(clone, "--use-git-credentials")
        self.assertEqual((code, json.loads(err)["error"]), (2, "git-credentials-missing"), out + err)
        self.assertEqual(self.server.seen_headers, [])

    def test_opt_in_is_refused_where_no_remote_is_read(self):
        code, result, err = self.workflow_cli("plan", "--use-git-credentials")
        self.assertEqual((code, result["reasons"]), (2, ["git-credentials-selection"]), result)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            rc.main([str(self.flow.repo), "--denylist", str(self.flow.testbed.denylist), "--use-git-credentials"])
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(self.helper_calls(), [])


if __name__ == "__main__":
    unittest.main()

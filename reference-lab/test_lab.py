"""Exercise the fixed reference tasks over HTTPS with a disposable local CA."""

from html.parser import HTMLParser
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
LOOPBACK = "127.0.0.1"


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.destinations = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.destinations.append(dict(attrs).get("href"))


class ReferenceLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        nginx = shutil.which("nginx")
        openssl = shutil.which("openssl")
        if nginx is None or openssl is None:
            raise RuntimeError("Reference lab tests require nginx and openssl on PATH")

        temporary = tempfile.TemporaryDirectory(prefix="check-tor-reference-lab-")
        cls.addClassCleanup(temporary.cleanup)
        prefix = Path(temporary.name)
        shutil.copyfile(HERE / "routes.conf", prefix / "routes.conf")

        # Ask the OS for a free port and let nginx bind it. The process and
        # per-run certificate are checked before requests exercise the routes.
        with socket.socket() as reserve:
            reserve.bind((LOOPBACK, 0))
            cls.port = reserve.getsockname()[1]
        config = (HERE / "nginx.conf").read_text(encoding="utf-8")
        (prefix / "nginx.conf").write_text(
            config.replace("127.0.0.1:18443", f"{LOOPBACK}:{cls.port}"),
            encoding="utf-8",
        )

        (prefix / "openssl.cnf").write_text(
            "[req]\ndistinguished_name = dn\nx509_extensions = server\n"
            "[dn]\n[server]\nsubjectAltName = IP:127.0.0.1\n",
            encoding="ascii",
        )
        cls.run_tool(
            [openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-subj", "/CN=reference lab test", "-config", "openssl.cnf",
             "-out", "tls.crt", "-keyout", "tls.key"],
            cwd=prefix,
        )
        cls.prefix = prefix
        cls.certificate = prefix / "tls.crt"
        cls.context = ssl.create_default_context(cafile=str(cls.certificate))
        command = [nginx, "-p", f"{prefix}/", "-c", "nginx.conf", "-e", "stderr"]
        cls.run_tool(command + ["-t"], cwd=prefix)
        process = subprocess.Popen(
            command + ["-g", "daemon off; master_process off;"], stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True,
        )
        cls.addClassCleanup(cls.stop_server, process)
        for _ in range(100):
            if process.poll() is not None:
                _, error = process.communicate(timeout=2)
                raise RuntimeError(f"nginx exited during startup: {error}")
            try:
                status, _, _ = cls.request("GET", "/normal")
            except ConnectionRefusedError:
                time.sleep(0.025)
            else:
                if status != 200 or process.poll() is not None:
                    raise RuntimeError("nginx did not serve the expected startup route")
                return
        raise RuntimeError("nginx did not start within the loopback test deadline")

    @staticmethod
    def run_tool(args, cwd):
        result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise RuntimeError(f"{Path(args[0]).name} failed: {result.stderr}")

    @staticmethod
    def stop_server(process):
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)

    @classmethod
    def request(cls, method, path, body=None, headers=None):
        client = http.client.HTTPSConnection(LOOPBACK, cls.port, context=cls.context, timeout=2)
        try:
            client.request(method, path, body=body, headers=headers or {})
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(8193)
        finally:
            client.close()

    def test_normal_task_has_one_first_party_link(self):
        status, headers, body = self.request("GET", "/normal")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(b"open from 9 a.m. to 5 p.m.", body)
        links = Links()
        links.feed(body.decode("utf-8"))
        self.assertEqual(links.destinations, ["/normal/complete"])
        status, _, body = self.request("GET", links.destinations[0])
        self.assertEqual(status, 200)
        self.assertIn(b"reading room is on the ground floor", body)

    def test_accepted_task_is_a_terminal_readable_202(self):
        status, headers, body = self.request("GET", "/accepted")
        self.assertEqual(status, 202)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("Location", headers)
        self.assertNotIn("Set-Cookie", headers)
        self.assertIn(b"accepted and is pending", body)
        self.assertEqual(int(headers["Content-Length"]), len(body))
        self.assertLess(len(body), 1024)
        links = Links()
        links.feed(body.decode("utf-8"))
        self.assertEqual(links.destinations, [])
        head_status, head_headers, head_body = self.request("HEAD", "/accepted")
        self.assertEqual(head_status, 202)
        self.assertEqual(head_headers["Content-Length"], headers["Content-Length"])
        self.assertEqual(head_body, b"")

    def test_scanner_probe_labels_normal_and_accepted_differently(self):
        # Use the shared target probe directly so it never contacts the Tor API.
        bridge = HERE.parent / "check_tor_probe.zsh"
        for route, status, verdict in (("/normal", 200, "PASS"), ("/accepted", 202, "CHALLENGE")):
            with self.subTest(route=route):
                request_dir = self.prefix / f"probe-{status}"
                request_dir.mkdir()
                result = subprocess.run(
                    ["zsh", str(bridge), str(request_dir), "direct",
                     f"https://{LOOPBACK}:{self.port}{route}", "3", "1", "target"],
                    env={
                        "PATH": os.environ.get("PATH", os.defpath),
                        "HOME": str(self.prefix),
                        "CURL_CA_BUNDLE": str(self.certificate),
                        "SSL_CERT_FILE": str(self.certificate),
                    },
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(result.stdout)
                self.assertIsNone(record["local_error"], record)
                self.assertEqual(record["curl_exit"], 0, record)
                self.assertEqual(record["http_status"], status, record)
                self.assertEqual(record["verdict"], verdict, record)
                self.assertEqual(record["redirect_count"], 0, record)
                self.assertFalse(record["body_limited"], record)

    def test_other_routes_and_requests_cannot_add_behaviors(self):
        status, headers, _ = self.request("POST", "/accepted")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET, HEAD")
        self.assertEqual(self.request("GET", "/accepted", body=b"x")[0], 400)
        self.assertEqual(self.request("GET", "/accepted", body=b"x" * 1025)[0], 400)
        self.assertEqual(
            self.request("GET", "/accepted", body=b"0\r\n\r\n",
                         headers={"Transfer-Encoding": "chunked"})[0],
            400,
        )
        self.assertEqual(self.request("GET", "/accepted", headers={"X-Large": "x" * 8192})[0], 400)
        self.assertEqual(self.request("GET", "/routes.conf")[0], 404)
        self.assertEqual(self.request("GET", "/tls.key")[0], 404)
        self.assertEqual(self.request("GET", "/")[0], 404)


if __name__ == "__main__":
    unittest.main(catchbreak=True)

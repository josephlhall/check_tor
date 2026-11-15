"""Exercise the fixed reference tasks over HTTPS with a disposable local CA."""

from contextlib import ExitStack
from html.parser import HTMLParser
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from lab_fixture import (
    HERE, LOOPBACK, Processes, direct_probe, nginx_fixture, private_env, tls_certificate,
)


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.destinations = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.destinations.append(dict(attrs).get("href"))


class NginxLabTestCase(unittest.TestCase):
    routes_file = HERE / "routes.conf"
    startup_path = "/normal"
    listen_ipv6 = False

    @classmethod
    def stage_conditions(cls, prefix):
        pass

    @classmethod
    def setUpClass(cls):
        nginx = shutil.which("nginx")
        openssl = shutil.which("openssl")
        if nginx is None or openssl is None:
            raise RuntimeError("Reference lab tests require nginx and openssl on PATH")

        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        cls.prefix = Path(stack.enter_context(
            tempfile.TemporaryDirectory(prefix="check-tor-reference-lab-")
        ))
        cls.stage_conditions(cls.prefix)
        cls.processes = Processes()
        cls.certificate = tls_certificate(cls.prefix, openssl, cls.processes)
        cls.fixture = stack.enter_context(nginx_fixture(
            cls.prefix, cls.certificate, nginx, cls.processes,
            routes_file=cls.routes_file, startup_path=cls.startup_path,
            listen_ipv6=cls.listen_ipv6,
        ))
        cls.port = cls.fixture.port
        cls.context = cls.fixture.context

    @classmethod
    def request(cls, method, path, body=None, headers=None, host=LOOPBACK):
        return cls.fixture.request(method, path, body=body, headers=headers, host=host)

    def probe(self, route):
        env = private_env(self.prefix, os.environ.get("PATH", os.defpath))
        env.update(CURL_CA_BUNDLE=str(self.certificate), SSL_CERT_FILE=str(self.certificate))
        with tempfile.TemporaryDirectory(prefix="probe-", dir=self.prefix) as directory:
            return direct_probe(Path(directory), self.processes, "zsh",
                                self.port, route, 3, env)


class ReferenceLabTests(NginxLabTestCase):
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
        for route, status, verdict in (("/normal", 200, "PASS"), ("/accepted", 202, "CHALLENGE")):
            with self.subTest(route=route):
                record = self.probe(route)
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
        for route in ("/client", "/client/complete", "/tor-diff", "/tor-diff/complete"):
            self.assertEqual(self.request("GET", route)[0], 404)


if __name__ == "__main__":
    unittest.main(catchbreak=True)

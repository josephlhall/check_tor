"""Exercise real curl certificate verification through the direct probe."""

import http.server
import json
import os
import shutil
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOOPBACK = "127.0.0.1"


class LocalTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise RuntimeError("The local TLS tests require openssl on PATH")

        temporary = tempfile.TemporaryDirectory(prefix="check-tor-tls-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        # Supply only the executable search path and a disposable home. This
        # excludes ambient proxy credentials and certificate configuration.
        cls.environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": temporary.name,
        }
        # A config file also works with LibreSSL versions that lack req -addext.
        (cls.directory / "openssl.cnf").write_text(
            "[req]\ndistinguished_name = dn\n[dn]\n"
            "[ca]\nbasicConstraints = critical, CA:true, pathlen:0\n"
            "keyUsage = critical, keyCertSign, cRLSign\n",
            encoding="ascii",
        )
        for name in ("trusted", "unrelated"):
            cls.run_openssl(
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-config",
                "openssl.cnf",
                "-extensions",
                "ca",
                "-days",
                "2",
                "-subj",
                f"/CN=check_tor {name} test CA",
                "-keyout",
                f"{name}.key",
                "-out",
                f"{name}.pem",
            )
        cls.make_leaf("matching", LOOPBACK, "1")
        cls.make_leaf("mismatching", "192.0.2.1", "2")

    @classmethod
    def run_openssl(cls, *args):
        process = subprocess.run(
            [cls.openssl, *args],
            cwd=cls.directory,
            env=cls.environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if process.returncode:
            raise RuntimeError(f"openssl {args[0]} failed\n{process.stderr}")

    @classmethod
    def make_leaf(cls, name, address, serial):
        cls.run_openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-config",
            "openssl.cnf",
            "-subj",
            "/CN=check_tor TLS test server",
            "-keyout",
            f"{name}.key",
            "-out",
            f"{name}.csr",
        )
        (cls.directory / "leaf.cnf").write_text(
            "basicConstraints = critical, CA:false\n"
            "keyUsage = critical, digitalSignature, keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n"
            f"subjectAltName = IP:{address}\n",
            encoding="ascii",
        )
        cls.run_openssl(
            "x509",
            "-req",
            "-in",
            f"{name}.csr",
            "-CA",
            "trusted.pem",
            "-CAkey",
            "trusted.key",
            "-set_serial",
            serial,
            "-sha256",
            "-days",
            "2",
            "-extfile",
            "leaf.cnf",
            "-out",
            f"{name}.pem",
        )

    def probe(self, leaf, ca):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            self.directory / f"{leaf}.pem", self.directory / f"{leaf}.key"
        )
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        class TLSServer(socketserver.TCPServer):
            # Use TCPServer to bind the numeric address without reverse DNS.
            timeout = 5

            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(5)
                try:
                    return context.wrap_socket(connection, server_side=True), address
                except OSError:
                    connection.close()
                    # Verification failures stop here, before the HTTP handler.
                    raise

        request_directory = tempfile.mkdtemp(prefix="probe-", dir=self.directory)
        with TLSServer((LOOPBACK, 0), Handler) as server:
            url = f"https://{LOOPBACK}:{server.server_address[1]}/fixture"
            worker = threading.Thread(target=server.handle_request, daemon=True)
            worker.start()
            try:
                process = subprocess.run(
                    [
                        "zsh",
                        str(ROOT / "check_tor_probe.zsh"),
                        request_directory,
                        "direct",
                        url,
                        "3",
                        "1",
                        "target",
                    ],
                    env=dict(
                        self.environment,
                        CURL_CA_BUNDLE=str(self.directory / f"{ca}.pem"),
                    ),
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            finally:
                worker.join(timeout=10)
                self.assertFalse(
                    worker.is_alive(), "Loopback TLS server did not finish"
                )

        self.assertEqual(process.returncode, 0, process.stderr)
        record = json.loads(process.stdout)
        self.assertIsNone(record["local_error"], record)
        return record, requests

    def test_trusted_certificate_reaches_http(self):
        record, requests = self.probe("matching", "trusted")
        self.assertEqual(record["curl_exit"], 0, record)
        self.assertEqual(record["http_status"], 200, record)
        self.assertEqual(record["verdict"], "PASS", record)
        self.assertEqual(requests, ["/fixture"])

    def assert_certificate_rejected(self, leaf, ca):
        record, requests = self.probe(leaf, ca)
        self.assertEqual(record["curl_exit"], 60, record)
        self.assertEqual(record["verdict"], "CERT", record)
        self.assertIsNone(record["http_status"], record)
        self.assertEqual(requests, [])

    def test_untrusted_issuer_is_rejected_before_http(self):
        self.assert_certificate_rejected("matching", "unrelated")

    def test_wrong_hostname_is_rejected_before_http(self):
        self.assert_certificate_rejected("mismatching", "trusted")


if __name__ == "__main__":
    unittest.main()

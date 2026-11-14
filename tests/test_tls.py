"""Exercise real curl TLS and transport failures through the direct probe."""

import http.server
import json
import os
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
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

    def server_context(self, leaf):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            self.directory / f"{leaf}.pem", self.directory / f"{leaf}.key"
        )
        return context

    def probe(self, leaf, ca):
        context = self.server_context(leaf)
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

    @contextmanager
    def fault_probe(self, scheme, timeout=2):
        # One client and one numeric loopback listener. Keep the listener and
        # probe files in the same scope as the child, including on Ctrl-C.
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            with socket.socket() as listener:
                listener.bind((LOOPBACK, 0))
                listener.listen(1)
                listener.settimeout(5)
                port = listener.getsockname()[1]
                url = f"{scheme}://{LOOPBACK}:{port}/fixture"
                with subprocess.Popen(
                    [
                        "zsh", str(ROOT / "check_tor_probe.zsh"), directory,
                        "direct", url, str(timeout), "1", "target",
                    ],
                    env=dict(
                        self.environment, CURL_CA_BUNDLE=str(self.directory / "trusted.pem")
                    ),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                ) as process:
                    try:
                        yield listener, process, Path(directory)
                    finally:
                        if process.returncode is None:
                            # The adapter can be inside a shell pipeline. Kill the
                            # whole group before Popen tries to wait for its pipes.
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            process.wait(timeout=5)

    def read_http_request(self, connection):
        deadline = time.monotonic() + 5
        request = b""
        while not request.endswith(b"\r\n\r\n"):
            self.assertLess(len(request), 4096, request)
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, "Timed out reading the fixture request")
            connection.settimeout(remaining)
            chunk = connection.recv(4096 - len(request))
            self.assertTrue(chunk, f"Peer closed before sending a complete request: {request!r}")
            request += chunk
        self.assertTrue(request.startswith(b"GET /fixture HTTP/1.1\r\n"), request)

    def fault_observation(self, process):
        output, stderr = process.communicate(timeout=8)
        self.assertEqual(process.returncode, 0, stderr)
        record = json.loads(output)
        self.assertIsNone(record["local_error"], record)
        self.assertIs(record["body_limited"], False, record)
        return record

    def test_stall_during_tls_handshake(self):
        with self.fault_probe("https") as (listener, process, _):
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                # A TLS handshake record arrived. Keep the connection open
                # without sending ServerHello so curl must hit its deadline.
                self.assertEqual(connection.recv(1), b"\x16")
                record = self.fault_observation(process)
        self.assertEqual(record["curl_exit"], 28, record)
        self.assertIsNone(record["http_status"], record)
        self.assertEqual(record["verdict"], "TIMEOUT", record)
        self.assertIn("no response in 2s", record["detail"])

    def test_stall_after_tls_handshake(self):
        context = self.server_context("matching")
        with self.fault_probe("https") as (listener, process, _):
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                with context.wrap_socket(connection, server_side=True) as encrypted:
                    # Curl reached HTTP on an authenticated connection. Keep
                    # it open without replying until the same deadline.
                    self.read_http_request(encrypted)
                    record = self.fault_observation(process)
        self.assertEqual(record["curl_exit"], 28, record)
        self.assertIsNone(record["http_status"], record)
        self.assertEqual(record["verdict"], "TIMEOUT", record)
        self.assertIn("TLS completed, then stalled for 2s", record["detail"])

    def test_empty_http_reply(self):
        with self.fault_probe("http") as (listener, process, _):
            connection, _ = listener.accept()
            with connection:
                self.read_http_request(connection)
                # FIN after consuming the request makes this an empty reply;
                # unread request bytes could turn a close into a reset.
                connection.shutdown(socket.SHUT_WR)
                record = self.fault_observation(process)
        self.assertEqual(record["curl_exit"], 52, record)
        self.assertIsNone(record["http_status"], record)
        self.assertEqual(record["verdict"], "DROP", record)

    def test_truncated_http_reply_retains_status_and_prefix(self):
        with self.fault_probe("http") as (listener, process, directory):
            connection, _ = listener.accept()
            with connection:
                self.read_http_request(connection)
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\npartial"
                )
                connection.shutdown(socket.SHUT_WR)
                record = self.fault_observation(process)
            self.assertEqual((directory / "body").read_bytes(), b"partial")
        self.assertEqual(record["curl_exit"], 18, record)
        self.assertEqual(record["http_status"], 200, record)
        self.assertEqual(record["verdict"], "DROP", record)

    def test_fault_probe_cleans_up_on_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            with self.fault_probe("http", timeout=10) as (listener, process, directory):
                connection, _ = listener.accept()
                self.addCleanup(connection.close)
                self.read_http_request(connection)
                raise KeyboardInterrupt
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual(listener.fileno(), -1)
        self.assertFalse(directory.exists())
        # The server socket is still open. EOF proves the curl descendant
        # closed its side, rather than just losing the adapter parent.
        connection.settimeout(3)
        self.assertEqual(connection.recv(1), b"")


if __name__ == "__main__":
    unittest.main()

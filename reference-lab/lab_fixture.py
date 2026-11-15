"""Disposable loopback TLS fixtures for the reference lab."""

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import time


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LOOPBACK = "127.0.0.1"


class LabError(RuntimeError):
    pass


class Interrupted(LabError):
    pass


class Processes:
    """Own subprocess sessions so cleanup also reaches their children."""

    interrupted = 0

    def cancel(self, signum, _frame):
        # Defer raising to a checkpoint where Popen has registered the group.
        self.interrupted = self.interrupted or signum

    def check(self):
        if self.interrupted:
            raise Interrupted(signal.Signals(self.interrupted).name)

    @staticmethod
    def signal_group(process, signum):
        deadline = time.monotonic() + 0.2
        while True:
            try:
                os.killpg(process.pid, signum)
                return True
            except ProcessLookupError:
                return False
            except PermissionError:
                # Darwin can transiently return EPERM for an exiting group.
                if process.poll() is not None:
                    return False
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)

    @contextmanager
    def session(self, args, *, grace=0.3, **kwargs):
        self.check()
        process = subprocess.Popen(
            args, start_new_session=True, stdin=subprocess.DEVNULL, **kwargs
        )
        try:
            yield process
        finally:
            if self.signal_group(process, signal.SIGTERM):
                deadline = time.monotonic() + grace
                while time.monotonic() < deadline:
                    process.poll()
                    if not self.signal_group(process, 0):
                        break
                    time.sleep(0.02)
                self.signal_group(process, signal.SIGKILL)
            process.wait(timeout=2)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def run(self, args, *, timeout=15, check=True, cwd=None, env=None, grace=0.3):
        deadline = time.monotonic() + timeout
        with self.session(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", cwd=cwd, env=env, grace=grace,
        ) as process:
            while True:
                self.check()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LabError(f"{Path(args[0]).name} exceeded its local deadline")
                try:
                    stdout, stderr = process.communicate(timeout=min(0.1, remaining))
                except subprocess.TimeoutExpired:
                    continue
                self.check()
                break
            if check and process.returncode:
                raise LabError(f"{Path(args[0]).name} failed: {stderr.strip()}")
            return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def tls_certificate(prefix, openssl, processes):
    (prefix / "openssl.cnf").write_text(
        "[req]\ndistinguished_name = dn\nx509_extensions = server\n"
        "[dn]\n[server]\nsubjectAltName = IP:127.0.0.1,IP:::1\n",
        encoding="ascii",
    )
    processes.run(
        [openssl, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "1", "-subj", "/CN=reference lab test", "-config", "openssl.cnf",
         "-out", "tls.crt", "-keyout", "tls.key"],
        cwd=prefix,
    )
    return prefix / "tls.crt"


class NginxFixture:
    def __init__(self, port, certificate):
        self.port = port
        self.certificate = certificate
        self.context = ssl.create_default_context(cafile=str(certificate))

    def request(self, method, path, body=None, headers=None, host=LOOPBACK):
        client = http.client.HTTPSConnection(host, self.port, context=self.context, timeout=2)
        try:
            client.request(method, path, body=body, headers=headers or {})
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(8193)
        finally:
            client.close()


@contextmanager
def nginx_fixture(prefix, certificate, nginx, processes, *,
                  routes_file=HERE / "routes.conf", startup_path="/normal",
                  listen_ipv6=False):
    # nginx needs the port in its config before it binds. The startup check
    # verifies the new process and per-run certificate before using either route.
    with socket.socket() as reserve:
        reserve.bind((LOOPBACK, 0))
        port = reserve.getsockname()[1]
    shutil.copyfile(routes_file, prefix / "routes.conf")
    config = (HERE / "nginx.conf").read_text(encoding="utf-8")
    listener = f"{LOOPBACK}:{port} ssl;"
    if listen_ipv6:
        listener += f"\n        listen [::1]:{port} ssl;"
    (prefix / "nginx.conf").write_text(
        config.replace("127.0.0.1:18443 ssl;", listener), encoding="utf-8",
    )
    command = [nginx, "-p", f"{prefix}/", "-c", "nginx.conf", "-e", "stderr"]
    processes.run(command + ["-t"], cwd=prefix)
    fixture = NginxFixture(port, certificate)
    with (prefix / "startup.log").open("w+", encoding="utf-8") as stderr:
        with processes.session(
            command + ["-g", "daemon off; master_process off;"],
            stdout=subprocess.DEVNULL, stderr=stderr, cwd=prefix,
        ) as process:
            for _ in range(100):
                processes.check()
                if process.poll() is not None:
                    stderr.seek(0)
                    raise LabError(f"nginx exited during startup: {stderr.read(8192)}")
                try:
                    status, _, _ = fixture.request("GET", startup_path)
                except ConnectionRefusedError:
                    time.sleep(0.025)
                else:
                    if status != 200 or process.poll() is not None:
                        raise LabError("nginx did not serve the expected startup route")
                    break
            else:
                raise LabError("nginx did not start within the loopback deadline")
            yield fixture


def private_env(prefix, path):
    return {
        "PATH": path,
        "HOME": str(prefix),
        "ZDOTDIR": str(prefix),
        "TMPDIR": str(prefix),
        "PYTHONDONTWRITEBYTECODE": "1",
        "LC_ALL": "C",
    }


def direct_probe(directory, processes, zsh, port, route, timeout, env):
    # Use the same transfer and classifier as the scanner without preflight.
    result = processes.run(
        [zsh, str(ROOT / "check_tor_probe.zsh"), str(directory), "direct",
         f"https://{LOOPBACK}:{port}{route}", str(timeout), "1", "target"],
        env=env, timeout=timeout + 5,
    )
    record = json.loads(result.stdout)
    if record["local_error"]:
        raise LabError(f"target probe setup failed: {record['local_error']}")
    return record

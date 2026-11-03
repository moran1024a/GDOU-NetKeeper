"""Offline daemon and PTY tests. Run after cargo build and cargo test."""

import argparse
import fcntl
import http.server
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import threading
import time
import tomllib
import urllib.parse


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("Timed out waiting for expected state")


class Portal(http.server.BaseHTTPRequestHandler):
    online = False
    reject = None
    hanging = False
    calls = []
    logins = 0
    login_times = []
    probe = None

    def do_GET(self):
        request = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(request.query)
        Portal.calls.append(request.path)
        if Portal.hanging:
            time.sleep(2)
            return
        if request.path.endswith("rad_user_info"):
            body = {"error": "ok" if Portal.online else "not_online_error"}
        elif request.path.endswith("get_challenge"):
            body = {"error": "ok", "challenge": "0123456789abcdef0123456789abcdef"}
        else:
            assert request.path.endswith("srun_portal")
            Portal.logins += 1
            Portal.login_times.append(time.monotonic())
            body = {"error": Portal.reject, "error_msg": "fixture rejection"} if Portal.reject else {"error": "ok"}
            if not Portal.reject:
                Portal.online = True
                Portal.probe.start()
        payload = (query["callback"][0] + "(" + json.dumps(body) + ");").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


class ProbeServer:
    """A loopback TCP endpoint which can really stop accepting connections."""
    def __init__(self):
        with socket.socket() as endpoint:
            endpoint.bind(("127.0.0.1", 0))
            self.port = endpoint.getsockname()[1]
        self.listener = None
        self.thread = None

    def start(self):
        if self.listener is not None:
            return
        endpoint = socket.socket()
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        endpoint.bind(("127.0.0.1", self.port))
        endpoint.listen()
        endpoint.settimeout(0.1)
        self.listener = endpoint

        def serve():
            while self.listener is endpoint:
                try:
                    connection, _ = endpoint.accept()
                    connection.close()
                except socket.timeout:
                    continue
                except OSError:
                    break
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def stop(self):
        endpoint, self.listener = self.listener, None
        if endpoint is not None:
            endpoint.close()
            self.thread.join(timeout=1)


def backend_tests(binary):
    probe = ProbeServer()
    Portal.probe = probe
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Portal)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="netkeeper-backend-") as directory:
            root = Path(directory)
            configuration = root / "config.toml"
            config_text = (
                f"username='fixture'\npassword='fixture-password'\nportal_url='http://127.0.0.1:{server.server_port}'\n"
                "ac_id=24\ninterface='lo'\nonline_interval_secs=30\nretry_intervals_secs=[1,2,3]\n"
                f"[probe]\nmode='tcp'\nprimary='127.0.0.2'\nbackups=['127.0.0.1']\ntcp_port={probe.port}\n"
                "interval_secs=1\ntimeout_secs=1\nfailure_threshold=3\n"
            )
            configuration.write_text(config_text)
            endpoint = root / "notify.sock"
            notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            notify.bind(str(endpoint))
            notify.setblocking(False)
            messages = []

            def notifications():
                while True:
                    try:
                        messages.append(notify.recv(16384).decode())
                    except BlockingIOError:
                        return messages

            def state():
                try:
                    return json.loads((root / "status.json").read_text())
                except FileNotFoundError:
                    return {}

            def launch():
                Portal.calls = []
                Portal.login_times = []
                Portal.logins = 0
                messages.clear()
                return subprocess.Popen(
                    [binary, "run", "--config", configuration, "--state-dir", root],
                    env=dict(os.environ, NOTIFY_SOCKET=str(endpoint)),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )

            def stop(process):
                count = len(Portal.calls)
                process.terminate()
                process.communicate(timeout=2)
                assert process.returncode == 0 and state()["phase"] == "stopped"
                assert state()["next_retry_at"] is None
                time.sleep(0.2)
                assert len(Portal.calls) == count

            process = None
            try:
                Portal.online = False
                Portal.reject = "password_error"
                process = launch()
                _, error = process.communicate(timeout=5)
                assert process.returncode == 78 and "password_error" in error
                assert state()["phase"] == "failed" and Portal.logins == 1
                assert not any("READY=1" in message for message in notifications())
                assert Portal.calls == ["/cgi-bin/rad_user_info", "/cgi-bin/get_challenge", "/cgi-bin/srun_portal"]
                assert "fixture-password" not in (root / "status.json").read_text()

                Portal.reject = None
                process = launch()
                wait_for(lambda: any("READY=1" in message for message in notifications()))
                assert state()["phase"] == "online" and Portal.logins == 1
                generation = state()["generation"]
                process.send_signal(signal.SIGUSR1)
                wait_for(lambda: state().get("generation", 0) > generation, timeout=0.8)
                generation = state()["generation"]
                calls = len(Portal.calls)
                wait_for(lambda: state().get("probe") is not None)
                assert state()["probe"]["reachable"] and "备用" in state()["probe"]["detail"]
                assert state()["generation"] == generation and len(Portal.calls) == calls

                # Two failed rounds must not trigger Portal traffic; a reachable
                # round resets the consecutive count, even if the primary fails.
                probe.stop()
                wait_for(lambda: state()["probe_failures"] == 2)
                assert len(Portal.calls) == calls
                probe.start()
                wait_for(lambda: state()["probe_failures"] == 0)
                assert len(Portal.calls) == calls

                # A real outage escalates on round three, then all three retry
                # stages apply. Frequent probe ticks and SIGUSR1 cannot bypass it.
                Portal.online = False
                Portal.reject = "server_busy"
                probe.stop()
                wait_for(lambda: state()["phase"] == "retrying")
                assert state()["probe_failures"] == 3
                assert state()["recovery_attempts"] == 1
                generation = state()["generation"]
                calls = len(Portal.calls)
                process.send_signal(signal.SIGUSR1)
                wait_for(lambda: state()["generation"] > generation, timeout=0.8)
                assert len(Portal.calls) == calls
                wait_for(lambda: state()["recovery_attempts"] >= 8, timeout=25)
                recovery_logins = Portal.login_times[1:]
                gaps = [b - a for a, b in zip(recovery_logins, recovery_logins[1:])]
                for actual, expected in zip(gaps, [1, 1, 1, 2, 2, 2, 3]):
                    assert actual >= expected - 0.1, (actual, expected)
                assert len(gaps) >= 7
                Portal.reject = None
                wait_for(lambda: state()["phase"] == "online", timeout=5)
                assert state()["probe_failures"] == 0 and state()["recovery_attempts"] == 0
                assert state()["next_retry_at"] is None

                # Portal online + unreachable public targets is an outage, not
                # another login request and not a false recovery.
                logins = Portal.logins
                probe.stop()
                wait_for(lambda: state()["phase"] == "retrying")
                assert "公网探测仍失败" in state()["detail"] and Portal.logins == logins
                wait_for(lambda: state()["recovery_attempts"] >= 2)
                assert Portal.logins == logins
                probe.start()
                wait_for(lambda: state()["phase"] == "online")
                assert Portal.logins == logins

                # Explicit credential rejection pauses all automatic requests.
                Portal.online = False
                Portal.reject = "password_error"
                probe.stop()
                wait_for(lambda: state()["phase"] == "paused")
                calls = len(Portal.calls)
                process.send_signal(signal.SIGUSR1)
                time.sleep(1.3)
                assert len(Portal.calls) == calls and state()["next_retry_at"] is None
                stop(process)

                # Low-frequency Portal checks remain active when probes pass.
                configuration.write_text(config_text.replace("online_interval_secs=30", "online_interval_secs=2"))
                Portal.reject = None
                process = launch()
                wait_for(lambda: any("READY=1" in message for message in notifications()))
                calls = len(Portal.calls)
                wait_for(lambda: len(Portal.calls) > calls, timeout=4)
                assert Portal.logins == 1
                stop(process)

                # SIGTERM interrupts an in-flight initial request before any
                # external HTTP fallback can occur.
                notifications()
                Portal.hanging = True
                process = launch()
                wait_for(lambda: bool(Portal.calls))
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=1)
                assert process.returncode == 0
                assert not any("READY=1" in message for message in notifications())
                assert state()["phase"] == "stopped"
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()
                notify.close()
    finally:
        server.shutdown()
        server.server_close()
        probe.stop()
    print("Daemon startup, fallback, failure threshold, staged retries, outage recovery, pause, periodic checks, and stop: PASS")

def tui_tests(test_binary):
    class DiscoveryPortal(http.server.BaseHTTPRequestHandler):
        hanging = False
        calls = 0

        def do_GET(self):
            assert self.path == "/", self.path
            DiscoveryPortal.calls += 1
            if DiscoveryPortal.hanging:
                time.sleep(1)
            body = b"<script>var ac_id=37;</script><p>SRUN online</p>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_):
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), DiscoveryPortal) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            _tui_tests(test_binary, server, DiscoveryPortal)
        finally:
            server.shutdown()


def _tui_tests(test_binary, server, handler):
    portal = f"http://127.0.0.1:{server.server_port}"
    with tempfile.TemporaryDirectory(prefix="netkeeper-tui-") as directory:
        root = Path(directory)
        configuration = root / "config.toml"
        configuration.write_text(
            f"username='fixture'\npassword='visible-old'\nportal_url='{portal}'\n"
            "ac_id=24\ninterface='missing-test0'\n"
        )
        for save in (True, False):
            before = configuration.read_bytes()
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
            original_mode = termios.tcgetattr(slave)
            process = subprocess.Popen(
                [test_binary, "--ignored", "--exact", "tui::tests::interactive_settings_fixture", "--nocapture"],
                stdin=slave, stdout=slave, stderr=slave,
                env=dict(os.environ, TERM="xterm-256color", NETKEEPER_UI_TEST_CONFIG=str(configuration),
                         NETKEEPER_UI_TEST_SAVED="yes" if save else "no"),
            )
            output = bytearray()

            def drain(duration=0.1):
                deadline = time.monotonic() + duration
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.02)[0]:
                        try:
                            output.extend(os.read(master, 65536))
                        except OSError:
                            break

            def send(keys):
                os.write(master, keys)
                drain()

            try:
                drain(0.4)
                assert "NetKeeper 设置" in output.decode(errors="replace")
                if save:
                    send(b"\r")  # Interface list.
                    assert "选择校园网网卡" in output.decode(errors="replace")
                    send(b"\x1b[H\r")  # Automatic route, not a numeric input.
                    send(b"\x1b[B\r\x15updated-user\r")
                    send(b"\x1b[B\r\x15" + "plain-pass-测试123".encode() + b"\r")
                    assert "plain-pass-测试123" in output.decode(errors="replace")
                    send(b"\x1b[H" + b"\x1b[B" * 8 + b"\r")  # Auto-discover from known Portal.
                    wait_for(lambda: handler.calls == 1)
                    drain(0.2)
                    assert "ac_id=37" in output.decode(errors="replace")
                    send(b"\r")  # Confirm detected parameters.
                    assert "接入点 ac_id：37" in output.decode(errors="replace")
                    send(b"\x1b[B\r" + (portal + "/srun_portal_pc?ac_id=42").encode() + b"\r")
                    assert "ac_id=42" in output.decode(errors="replace")
                    send(b"\r")  # Confirm imported parameters; no extra HTTP request.
                    send(b"\x1b[H" + b"\x1b[B" * 6 + b"\r")  # Probe settings.
                    assert "公网探测设置" in output.decode(errors="replace")
                    send(b"\r\x1b[B\r")  # ICMP -> TCP, using a selector.
                    send(b"\x1b[B\r\x15127.0.0.1\r")
                    send(b"\x1b[B\r\x15\r")  # Clear one optional backup.
                    send(b"\x1b[F\r")  # Return without committing yet.
                    send(b"\x1b[F\x1b[A\r")  # Save.
                else:
                    handler.hanging = True
                    send(b"\x1b[H" + b"\x1b[B" * 8 + b"\r")
                    wait_for(lambda: handler.calls == 2)
                    send(b"\x1b")  # Cancel discovery while its request is pending.
                    send(b"\x1b[H")
                    send(b"\x1b[B\r\x15unsaved-value\x1b")  # Cancel edit.
                    send(b"\x1b")  # Cancel settings.
                process.wait(timeout=3)
                drain()
                assert process.returncode == 0, output.decode(errors="replace")
                assert termios.tcgetattr(slave) == original_mode, "Terminal mode was not restored"
                if save:
                    settings = tomllib.loads(configuration.read_text())
                    assert settings["username"] == "updated-user"
                    assert settings["password"] == "plain-pass-测试123"
                    assert settings["portal_url"] == portal and settings["ac_id"] == 42
                    assert settings["probe"]["mode"] == "tcp"
                    assert settings["probe"]["primary"] == "127.0.0.1"
                    assert len(settings["probe"]["backups"]) == 2
                    assert "interface" not in settings
                    assert configuration.stat().st_mode & 0o777 == 0o600
                else:
                    assert configuration.read_bytes() == before
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(master)
                os.close(slave)
    assert handler.calls == 2
    print("PTY automatic discovery, URL import, cancellation, settings save and terminal restoration: PASS")


def find_test_binary():
    # cargo build also puts the ordinary CLI in deps; it cannot run the fixture.
    candidates = sorted(
        (path for path in Path("target/debug/deps").glob("netkeeper-*") if path.is_file() and os.access(path, os.X_OK)),
        key=lambda path: path.stat().st_mtime, reverse=True,
    )
    for path in candidates:
        result = subprocess.run([path, "--list"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and "tui::tests::interactive_settings_fixture: test" in result.stdout:
            return path
    raise RuntimeError("Run cargo test --locked before the PTY tests")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/netkeeper"))
    parser.add_argument("--test-binary", type=Path)
    parser.add_argument("--settings-only", action="store_true", help="only test the settings TUI")
    args = parser.parse_args()
    test_binary = args.test_binary or find_test_binary()
    if not args.settings_only:
        backend_tests(args.binary.resolve())
    tui_tests(test_binary.resolve())

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
    reject = False
    hanging = False
    calls = []
    logins = 0

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
            body = {"error": "password_error", "error_msg": "wrong password"} if Portal.reject else {"error": "ok"}
            if not Portal.reject:
                Portal.online = True
        payload = (query["callback"][0] + "(" + json.dumps(body) + ");").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def backend_tests(binary):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Portal)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="netkeeper-backend-") as directory:
            root = Path(directory)
            configuration = root / "config.toml"
            configuration.write_text(
                f"username='fixture'\npassword='fixture-password'\nportal_url='http://127.0.0.1:{server.server_port}'\n"
                "ac_id=24\ninterface='lo'\nonline_interval_secs=1\nretry_interval_secs=1\n"
            )
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
                messages.clear()
                return subprocess.Popen(
                    [binary, "run", "--config", configuration, "--state-dir", root],
                    env=dict(os.environ, NOTIFY_SOCKET=str(endpoint)),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )

            process = None
            try:
                # First failure must exit, without readiness or a background retry.
                Portal.reject = True
                process = launch()
                _, error = process.communicate(timeout=5)
                assert process.returncode == 78 and "password_error" in error
                assert state()["phase"] == "failed" and Portal.logins == 1
                assert not any("READY=1" in message for message in notifications())
                assert Portal.calls == ["/cgi-bin/rad_user_info", "/cgi-bin/get_challenge", "/cgi-bin/srun_portal"]
                assert "fixture-password" not in (root / "status.json").read_text()

                # Confirm readiness, then an unsuccessful reconnect followed by recovery.
                Portal.reject = False
                process = launch()
                wait_for(lambda: any("READY=1" in message for message in notifications()))
                assert state()["phase"] == "online" and Portal.logins == 2
                generation = state()["generation"]
                process.send_signal(signal.SIGUSR1)
                wait_for(lambda: state().get("generation", 0) > generation, timeout=0.8)
                assert state()["phase"] == "online" and Portal.logins == 2
                Portal.online = False
                Portal.reject = True
                wait_for(lambda: state().get("phase") == "retrying")
                assert process.poll() is None
                Portal.reject = False
                wait_for(lambda: state().get("phase") == "online")
                before = len(Portal.calls)
                started = time.monotonic()
                process.terminate()
                process.communicate(timeout=2)
                assert process.returncode == 0 and time.monotonic() - started < 2
                assert state()["phase"] == "stopped"
                time.sleep(0.2)
                assert len(Portal.calls) == before

                # SIGTERM interrupts an in-flight initial request, not just the sleep.
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
    print("Daemon readiness, fresh online confirmation, first failure, recovery, and stop cancellation: PASS")


def tui_tests(test_binary):
    with tempfile.TemporaryDirectory(prefix="netkeeper-tui-") as directory:
        root = Path(directory)
        configuration = root / "config.toml"
        configuration.write_text(
            "username='fixture'\npassword='visible-old'\nportal_url='http://127.0.0.1'\n"
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
                    send(b"\x1b[F\x1b[A\r")  # Save.
                else:
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
    print("PTY arrows, interface selection, plaintext fields, save/cancel, and terminal restoration: PASS")


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
    args = parser.parse_args()
    test_binary = args.test_binary or find_test_binary()
    backend_tests(args.binary.resolve())
    tui_tests(test_binary.resolve())

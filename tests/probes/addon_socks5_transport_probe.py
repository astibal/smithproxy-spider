"""Observe live SOCKS5 authentication behavior in mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import time


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_for_proxy(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError("Reference proxy exited before binding SOCKS5\n" + output)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                return
        except OSError:
            time.sleep(.05)
    raise TimeoutError("Reference proxy did not bind SOCKS5 within five seconds")


def authenticate(port, case, username, password):
    username_bytes = username if isinstance(username, bytes) else username.encode()
    password_bytes = password if isinstance(password, bytes) else password.encode()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.sendall(b"\x05\x01\x02")
        method = client.recv(2)
        client.sendall(
            b"\x01"
            + bytes((len(username_bytes),))
            + username_bytes
            + bytes((len(password_bytes),))
            + password_bytes
        )
        result = client.recv(2)
    return {
        "case": case,
        "method_reply": method.hex(),
        "auth_reply": result.hex(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_socks5_transport_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"socks5@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "--proxyauth", "alice:secret",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        wait_for_proxy(proxy_port, process)
        wire = [
            authenticate(proxy_port, "addon-allows", "override", "allow"),
            authenticate(proxy_port, "addon-rejects", "alice", "secret"),
            authenticate(proxy_port, "non-utf8", b"\xff", b"\xfe"),
        ]
        time.sleep(.1)
    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "hooks": hooks,
        "wire": wire,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference SOCKS5 behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()

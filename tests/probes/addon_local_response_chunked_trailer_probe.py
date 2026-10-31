"""Observe the bounded HTTP/1 chunked-trailer local-response failure.

The reference is given a locally constructed response with explicit chunked
framing and trailers. The probe records bytes received before a short idle
deadline, then terminates the isolated reference process. No origin is used.
"""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import time


def reserve_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_for_proxy(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Reference proxy exited before accepting connections")
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=.2)
        except OSError:
            time.sleep(.05)
            continue
        connection.close()
        return
    raise TimeoutError("Reference proxy did not start within five seconds")


def exchange(port):
    wire = (
        b"POST http://example.invalid/trailers-chunked HTTP/1.1\r\n"
        b"Host: example.invalid\r\n"
        b"Content-Length: 4\r\n"
        b"Connection: close\r\n\r\n"
        b"test"
    )
    received = bytearray()
    timed_out = False
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.settimeout(.5)
        connection.sendall(wire)
        while True:
            try:
                chunk = connection.recv(65535)
            except TimeoutError:
                timed_out = True
                break
            if not chunk:
                break
            received.extend(chunk)
    return {
        "timed_out": timed_out,
        "wire": bytes(received).decode("latin-1"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    port = reserve_port()
    addon = Path(__file__).with_name("addon_local_response_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        wait_for_proxy(port, process)
        exchange_result = exchange(port)
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
        **exchange_result,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference chunked-trailer behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()

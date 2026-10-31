"""Observe UDP addon lifecycle in an isolated mitmproxy 12.3.1.

This opt-in black-box probe invokes an independently installed mitmdump in
reverse UDP mode and a disposable loopback origin. It never imports reference
implementation source.
"""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import threading
import time


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def udp_listener_present(port):
    wanted = f"{port:04X}"
    for table in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            lines = Path(table).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 1 and fields[1].partition(":")[2].upper() == wanted:
                return True
    return False


def wait_for_proxy(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError("Reference proxy exited before binding UDP\n" + output)
        if udp_listener_present(port):
            return
        time.sleep(.05)
    raise TimeoutError("Reference proxy did not bind UDP within five seconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    origin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    origin.bind(("127.0.0.1", 0))
    origin.settimeout(5)
    origin_port = origin.getsockname()[1]
    origin_observation = {}
    origin_error = []

    def serve():
        try:
            data, peer = origin.recvfrom(65535)
            origin_observation["received"] = data.decode("latin-1")
            origin.sendto(b"echo:" + data, peer)
        except Exception as error:
            origin_error.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_udp_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"reverse:udp://127.0.0.1:{origin_port}",
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    client_received = None
    try:
        wait_for_proxy(proxy_port, process)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(("127.0.0.1", 0))
            client.settimeout(5)
            client.sendto(b"hello", ("127.0.0.1", proxy_port))
            data, _ = client.recvfrom(65535)
            client_received = data.decode("latin-1")
        server.join(5)
        time.sleep(.1)
    finally:
        origin.close()
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    if origin_error:
        raise RuntimeError("Origin failed: " + repr(origin_error))
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "origin": origin_observation,
        "client_received": client_received,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference UDP behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()

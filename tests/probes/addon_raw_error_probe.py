"""Observe raw upstream failures from isolated mitmproxy 12.3.1.

The targets are deliberately unbound loopback ports. The reference package is
used only as a black-box executable; no implementation module is imported.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time


def reserve_unbound_port(socket_type):
    reservation = socket.socket(socket.AF_INET, socket_type)
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    reservation.close()
    return port


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


def wait_for_proxy(protocol, port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError("Reference proxy exited during startup\n" + output)
        if protocol == "udp":
            if udp_listener_present(port):
                return
        else:
            try:
                connection = socket.create_connection(("127.0.0.1", port), timeout=.2)
            except OSError:
                pass
            else:
                connection.close()
                return
        time.sleep(.05)
    raise TimeoutError("Reference proxy did not start within five seconds")


def run_case(reference, protocol, target_port=None):
    socket_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    if target_port is None:
        target_port = reserve_unbound_port(socket_type)
    proxy_port = reserve_unbound_port(socket_type)
    addon = Path(__file__).with_name("addon_raw_control_addon.py")
    environment = dict(os.environ, RAW_CONTROL_SCENARIO="observe-error")
    process = subprocess.Popen([
        reference,
        "--mode", f"reverse:{protocol}://127.0.0.1:{target_port}",
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    client_outcome = "eof"
    received = bytearray()
    try:
        wait_for_proxy(protocol, proxy_port, process)
        if protocol == "tcp":
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
                client.settimeout(2)
                client.sendall(b"hello")
                try:
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        received.extend(chunk)
                except TimeoutError:
                    client_outcome = "timeout"
                except ConnectionResetError:
                    client_outcome = "reset"
        else:
            client_outcome = "timeout"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.bind(("127.0.0.1", 0))
                client.settimeout(2)
                client.sendto(b"hello", ("127.0.0.1", proxy_port))
                client.sendto(b"again", ("127.0.0.1", proxy_port))
                try:
                    data, _ = client.recvfrom(65535)
                    received.extend(data)
                    client_outcome = "datagram"
                except TimeoutError:
                    pass
        time.sleep(.2)
    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    events = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    active_ids = {
        event["flow_id"] for event in events
        if event["message_count"] > 0
    }
    if not active_ids and events:
        active_ids.add(events[-1]["flow_id"])
    events = [event for event in events if event["flow_id"] in active_ids]
    for event in events:
        del event["flow_id"]
    return {
        "client_received": bytes(received).decode("latin-1"),
        "client_outcome": client_outcome,
        "hooks": events,
    }


def run_tcp_reset(reference):
    origin = socket.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen(4)
    origin.settimeout(3)
    origin_port = origin.getsockname()[1]

    def serve():
        try:
            while True:
                connection, _ = origin.accept()
                connection.settimeout(1)
                data = connection.recv(4096)
                if not data:
                    connection.close()
                    continue
                connection.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_LINGER,
                    struct.pack("ii", 1, 0),
                )
                connection.close()
                return
        except (OSError, TimeoutError):
            return

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    try:
        return run_case(reference, "tcp", origin_port)
    finally:
        origin.close()
        server.join(3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    result = {
        "reference": "mitmproxy 12.3.1",
        "tcp_connect_refused": run_case(args.reference, "tcp"),
        "tcp_reset": run_tcp_reset(args.reference),
        "udp_unreachable": run_case(args.reference, "udp"),
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference raw error behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()

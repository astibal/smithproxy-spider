"""Record raw TCP/UDP control behavior from isolated mitmproxy 12.3.1.

The probe starts disposable reverse-mode proxies and loopback origins. It uses
the reference package only as a black-box executable and never imports its
implementation modules.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time


SCENARIOS = (
    "kill-start",
    "kill-client-message",
    "kill-server-message",
    "empty-client-message",
    "empty-server-message",
    "set-live-false",
    "set-custom-error",
    "tag-messages",
)


def reserve_port(socket_type):
    with socket.socket(socket.AF_INET, socket_type) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_for_tcp(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Reference proxy exited before accepting TCP")
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=.2)
        except OSError:
            time.sleep(.05)
            continue
        connection.close()
        return
    raise TimeoutError("Reference proxy did not accept TCP within five seconds")


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


def wait_for_udp(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Reference proxy exited before binding UDP")
        if udp_listener_present(port):
            return
        time.sleep(.05)
    raise TimeoutError("Reference proxy did not bind UDP within five seconds")


def run_proxy(reference, protocol, origin_port, scenario):
    socket_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    proxy_port = reserve_port(socket_type)
    addon = Path(__file__).with_name("addon_raw_control_addon.py")
    environment = dict(os.environ, RAW_CONTROL_SCENARIO=scenario)
    process = subprocess.Popen([
        reference,
        "--mode", f"reverse:{protocol}://127.0.0.1:{origin_port}",
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if protocol == "tcp":
        wait_for_tcp(proxy_port, process)
    else:
        wait_for_udp(proxy_port, process)
    return process, proxy_port


def finish_proxy(process):
    time.sleep(.1)
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
    return events


def relevant_events(events):
    active_ids = {
        event["flow_id"] for event in events
        if event["message_count"] > 0
    }
    if not active_ids and events:
        active_ids.add(events[-1]["flow_id"])
    selected = [event for event in events if event["flow_id"] in active_ids]
    for event in selected:
        del event["flow_id"]
    return selected


def read_tcp_client(client):
    received = bytearray()
    outcome = "eof"
    try:
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            received.extend(chunk)
    except TimeoutError:
        outcome = "timeout"
    return bytes(received).decode("latin-1"), outcome


def observe_tcp(reference, scenario):
    origin = socket.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen(4)
    origin.settimeout(3)
    origin_port = origin.getsockname()[1]
    observation = {"connections": 0, "received": []}

    def serve():
        try:
            while True:
                connection, _ = origin.accept()
                with connection:
                    connection.settimeout(1)
                    data = connection.recv(4096)
                    if not data:
                        continue
                    observation["connections"] += 1
                    observation["received"].append(data.decode("latin-1"))
                    connection.sendall(b"one:" + data)
                    if scenario == "tag-messages":
                        second = connection.recv(4096)
                        observation["received"].append(second.decode("latin-1"))
                        connection.sendall(b"two:" + second)
                    return
        except (OSError, TimeoutError):
            return

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    process, proxy_port = run_proxy(reference, "tcp", origin_port, scenario)
    client_received = ""
    client_outcome = "connect-error"
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
            client.settimeout(1)
            client.sendall(b"hello")
            if scenario == "tag-messages":
                time.sleep(.05)
                client.sendall(b"world")
            client_received, client_outcome = read_tcp_client(client)
    except OSError:
        pass
    server.join(3)
    origin.close()
    events = relevant_events(finish_proxy(process))
    return {
        "origin": observation,
        "client_received": client_received,
        "client_outcome": client_outcome,
        "hooks": events,
    }


def observe_udp(reference, scenario):
    origin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    origin.bind(("127.0.0.1", 0))
    origin.settimeout(2)
    origin_port = origin.getsockname()[1]
    observation = {"received": []}

    def serve():
        try:
            count = 2 if scenario == "tag-messages" else 1
            for index in range(count):
                data, peer = origin.recvfrom(65535)
                observation["received"].append(data.decode("latin-1"))
                origin.sendto(str(index + 1).encode() + b":" + data, peer)
        except (OSError, TimeoutError):
            return

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    process, proxy_port = run_proxy(reference, "udp", origin_port, scenario)
    received = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("127.0.0.1", 0))
        client.settimeout(1)
        payloads = (b"hello", b"world") if scenario == "tag-messages" else (b"hello",)
        for payload in payloads:
            client.sendto(payload, ("127.0.0.1", proxy_port))
            try:
                data, _ = client.recvfrom(65535)
                received.append(data.decode("latin-1"))
            except TimeoutError:
                received.append(None)
    server.join(3)
    origin.close()
    events = relevant_events(finish_proxy(process))
    return {
        "origin": observation,
        "client_received": received,
        "hooks": events,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    result = {"reference": "mitmproxy 12.3.1", "tcp": {}, "udp": {}}
    for scenario in SCENARIOS:
        result["tcp"][scenario] = observe_tcp(args.reference, scenario)
        result["udp"][scenario] = observe_udp(args.reference, scenario)

    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference raw control behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()

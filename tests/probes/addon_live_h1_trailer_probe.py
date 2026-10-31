"""Record HTTP/1 chunked trailer mutation through mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

from addon_live_http_contract import (
    H1_TRAILER_REQUEST, H1_TRAILER_RESPONSE, TRAILER_SOURCE,
    parse_http1_chunked,
)


def reserve_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_for_proxy(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError("Reference proxy exited before accepting connections\n" + output)
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=.2)
        except OSError:
            time.sleep(.05)
            continue
        connection.close()
        return
    raise TimeoutError("Reference proxy did not start within five seconds")


def receive_chunked(connection):
    wire = bytearray()
    while True:
        chunk = connection.recv(65535)
        if not chunk:
            raise RuntimeError(
                "Connection closed before a complete chunked message: "
                + repr(bytes(wire))
            )
        wire.extend(chunk)
        head, marker, tail = bytes(wire).partition(b"\r\n\r\n")
        if marker and b"transfer-encoding: chunked" not in head.lower():
            content_length = None
            for line in head.split(b"\r\n")[1:]:
                name, colon, value = line.partition(b":")
                if colon and name.lower() == b"content-length":
                    content_length = int(value.strip())
            if content_length is not None and len(tail) >= content_length:
                raise RuntimeError(
                    "Expected chunked framing, received: " + repr(bytes(wire))
                )
        try:
            parsed = parse_http1_chunked(bytes(wire))
        except AssertionError:
            continue
        if parsed["extra"]:
            raise RuntimeError("Unexpected bytes after the chunked message")
        return bytes(wire), parsed


def normalized(parsed, *, request):
    result = {
        "body": parsed["body"].decode("latin-1"),
        "trailers": [
            field for field in parsed["trailers"]
            if field[0] in ("x-addon-trailer", "x-input-trailer", "x-remove")
        ],
    }
    if request:
        method, path, _ = parsed["start"].split(" ", 2)
        result.update({"method": method, "path": path})
    else:
        _, status, reason = parsed["start"].split(" ", 2)
        result.update({"status": int(status), "reason": reason})
    return result


def serve_origin(listener, observed, errors):
    try:
        connection, _ = listener.accept()
        with connection:
            _, parsed = receive_chunked(connection)
            observed.append(normalized(parsed, request=True))
            connection.sendall(H1_TRAILER_RESPONSE)
    except Exception as error:
        errors.append(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output")
    parser.add_argument("--expect")
    arguments = parser.parse_args()

    observed = []
    origin_errors = []
    origin = socket.socket()
    origin.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    origin.bind(("127.0.0.1", 0))
    origin.listen(1)
    server = threading.Thread(
        target=serve_origin, args=(origin, observed, origin_errors), daemon=True
    )
    server.start()

    proxy_port = reserve_port()
    with tempfile.TemporaryDirectory(prefix="addon-live-h1-trailers-") as directory:
        addon = Path(directory) / "addon.py"
        addon.write_text(TRAILER_SOURCE)
        process = subprocess.Popen([
            arguments.reference,
            "--mode", f"reverse:http://127.0.0.1:{origin.getsockname()[1]}",
            "--listen-host", "127.0.0.1",
            "--listen-port", str(proxy_port),
            "--set", "termlog_verbosity=error",
            "-s", str(addon),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        client_error = None
        parsed_response = None
        try:
            wait_for_proxy(proxy_port, process)
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
                client.settimeout(2)
                client.sendall(H1_TRAILER_REQUEST)
                _, parsed_response = receive_chunked(client)
        except Exception as error:
            client_error = error
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
    server.join(5)
    if server.is_alive():
        raise TimeoutError("Upstream HTTP/1 server did not finish")
    reference_limitation = "NotImplementedError: HTTP trailers are not implemented yet."
    if reference_limitation in output:
        result = {
            "reference": "mitmproxy 12.3.1",
            "outcome": "proxy-error",
            "error": reference_limitation,
            "request_forwarded": bool(observed),
            "client_response": parsed_response is not None,
        }
    elif origin_errors:
        raise RuntimeError(
            f"Origin exchange failed: {origin_errors[0]}\nReference output:\n{output}"
        ) from origin_errors[0]
    elif client_error is not None:
        raise RuntimeError(
            f"Client exchange failed: {client_error}\nReference output:\n{output}"
        ) from client_error
    else:
        result = {
            "reference": "mitmproxy 12.3.1",
            "request": observed[0],
            "response": normalized(parsed_response, request=False),
        }
    if arguments.expect:
        expected = json.loads(Path(arguments.expect).read_text())
        if result != expected:
            raise AssertionError("Reference live HTTP/1 trailer behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()

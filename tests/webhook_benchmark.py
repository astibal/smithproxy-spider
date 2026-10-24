#!/usr/bin/env python3
"""Closed-loop, loopback HTTP benchmark. Never connects to an existing Spider.

Each case owns a fresh Spider and temporary storage. The fake Smithproxy only
registers the callback; timed requests traverse the real Spider webhook handler.
No browser, TLS, proxy forwarding or network latency is included.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import http.client
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit
from http.server import ThreadingHTTPServer

from fake_smithproxy import API_KEY, Handler
from integration_chain import get_json, post_json


def percentile(values, percent):
    """Nearest-rank percentile; return null when no requests succeeded."""
    if not values:
        return None
    return sorted(values)[max(0, math.ceil(len(values) * percent / 100) - 1)]


def latency(values):
    return {name: percentile(values, percent)
            for name, percent in (("p50", 50), ("p95", 95), ("p99", 99), ("max", 100))}


@contextmanager
def server(binary):
    Handler.callback = None
    api = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=api.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="spider-webhook-bench-") as root:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            # Port reservation has a small bind race: startup fails, never reuse
            # another server. A fresh random API token also prevents cross-talk.
            token = os.urandom(24).hex()
            env = dict(os.environ, SPIDER_TOKEN=token,
                       SPIDER_COLLECTION_DIR=root + "/collections",
                       SPIDER_STORAGE_DIR=root + "/storage")
            proxy = f"http://127.0.0.1:{api.server_port}"
            base = f"http://127.0.0.1:{port}"
            with open(root + "/server.log", "w+") as log:
                process = subprocess.Popen([
                    binary, "--bind", "127.0.0.1", "--port", str(port),
                    "--smithproxy-url", proxy, "--callback-url", base + "/webhook",
                ], env=env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError("Spider exited during startup")
                        try:
                            get_json(base + "/api/inspection", token)
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise RuntimeError("Spider startup timed out")
                            time.sleep(.05)
                    post_json(base + "/api/config/smithproxy", {
                        "url": proxy, "api_key": API_KEY, "verify_tls": False,
                    }, token)
                    while not Handler.callback:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Callback registration timed out")
                        time.sleep(.01)
                    yield base, token, Handler.callback
                except Exception:
                    log.flush()
                    log.seek(0)
                    print(log.read()[-8000:], flush=True)
                    raise
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    finally:
        api.shutdown()
        api.server_close()
        thread.join()


def batch(callback, size, count, concurrency, scripted):
    target = urlsplit(callback)
    payload = b"a" * size
    expected = base64.b64encode(payload.upper()).decode()
    # Fixed session per producer: measure repeated callbacks, not creation of an
    # unbounded number of sessions. Source bytes and JSON are prepared untimed.
    bodies = [json.dumps({
        "action": "connection-content", "id": f"benchmark-{i}",
        "details": {"info": {"side": "L", "content": base64.b64encode(payload).decode(),
                              "session": f"tcp_10.0.0.1:{10000+i}+tcp_10.0.0.2:80"}},
    }).encode() for i in range(concurrency)]
    barrier = threading.Barrier(concurrency + 1)

    def producer(index):
        connection = http.client.HTTPConnection(target.hostname, target.port, timeout=5)
        results = []
        barrier.wait()
        for _ in range(index, count, concurrency):
            start = time.perf_counter_ns()
            outcome = "ok"
            try:
                connection.request("POST", target.path, bodies[index],
                                   {"Content-Type": "application/json"})
                response = connection.getresponse()
                raw = response.read()
                if response.status != 200:
                    outcome = f"http_{response.status}"
                else:
                    reply = json.loads(raw)
                    if scripted:
                        if reply.get("action") == "unchanged":
                            outcome = "unexpected_unchanged"  # includes fail-open
                        elif reply.get("action") != "replace" or reply.get("content") != expected:
                            outcome = "incorrect_replacement"
                    elif reply.get("action") != "unchanged":
                        outcome = "unexpected_action"
            except (OSError, http.client.HTTPException, ValueError) as error:
                outcome = type(error).__name__
                connection.close()  # Next request may reconnect; never retry this one.
            results.append(((time.perf_counter_ns() - start) / 1e6, outcome))
        connection.close()
        return results

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(producer, i) for i in range(concurrency)]
        start = time.perf_counter()
        barrier.wait()
        results = [item for future in futures for item in future.result()]
        elapsed = time.perf_counter() - start
    good = [duration for duration, outcome in results if outcome == "ok"]
    errors = {}
    for _, outcome in results:
        if outcome != "ok":
            errors[outcome] = errors.get(outcome, 0) + 1
    return {"requests": count, "successes": len(good), "errors": errors,
            "elapsed_seconds": elapsed, "requests_per_second": count / elapsed,
            "successful_requests_per_second": len(good) / elapsed,
            "successful_payload_mib_per_second": len(good) * size / elapsed / 2**20,
            "latency_ms_all": latency([duration for duration, _ in results]),
            "latency_ms_success": latency(good)}


def case(args, mode, size, concurrency):
    with server(str(args.binary.resolve())) as (base, token, callback):
        url = base + "/api/inspection"
        if mode == "script":
            state = get_json(url, token)
            _, state = post_json(url, {
                "operation": "deploy", "revision": state["revision"],
                "name": "Benchmark", "script": (
                    f"import time\ntime.sleep({args.script_delay_ms / 1000})\n"
                    if args.script_delay_ms else "") + "return api.bytes.upper()",
                "scope": "all", "instancing": "message",
            }, token)
            post_json(url, {"operation": "enable", "revision": state["revision"],
                           "id": state["chain"][0]["id"], "enabled": True}, token)
        warmup = batch(callback, size, args.warmup, concurrency, mode == "script")
        before = get_json(url, token)
        result = batch(callback, size, args.requests, concurrency, mode == "script")
        after = get_json(url, token)
        result.update(mode=mode, payload_bytes=size, concurrency=concurrency,
                      warmup_errors=warmup["errors"],
                      backend_runs=after["runs"] - before["runs"],
                      backend_errors=after["errors"] - before["errors"])
        if mode == "script":
            a, b = before["chain"][0], after["chain"][0]
            result.update(backend_rejected=b["rejected"] - a["rejected"],
                          worker_restarts=b["workers"]["restarts"] - a["workers"]["restarts"],
                          pool_cold_waits=b["workers"].get("cold_waits", 0) - a["workers"].get("cold_waits", 0),
                          pool_queue_wait_us=b["workers"].get("queue_wait_us", 0) - a["workers"].get("queue_wait_us", 0),
                          pool_max_queue_wait_us=b["workers"].get("max_queue_wait_us"),
                          pool_forced_recycles=b["workers"].get("forced_recycles", 0) - a["workers"].get("forced_recycles", 0),
                          pool_rotations=b["workers"].get("rotations", 0) - a["workers"].get("rotations", 0),
                          deployment_enabled=b["enabled"], suspended=b.get("suspended", False))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--requests", type=int, default=200, help="measured requests per case")
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--sizes", type=int, nargs="+", default=[64, 4096, 65536])
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 2, 4])
    parser.add_argument("--script-delay-ms", type=int, default=0,
                        help="artificial script sleep, 0..300 ms, for saturation checks")
    parser.add_argument("--output", type=Path, help="JSON report (overwrites this path)")
    args = parser.parse_args()
    if (not args.binary.is_file() or not 1 <= args.requests <= 100000
            or not 1 <= args.warmup <= 10000 or not all(1 <= s <= 1048576 for s in args.sizes)
            or not 0 <= args.script_delay_ms <= 300
            or not all(1 <= c <= min(64, args.requests, args.warmup) for c in args.concurrency)):
        parser.error("Invalid binary, counts, sizes (1..1 MiB) or concurrency (1..64 and <= counts)")
    with args.binary.open("rb") as binary_file:
        binary_hash = hashlib.file_digest(binary_file, "sha256").hexdigest()
    report = {"platform": platform.platform(), "python": platform.python_version(),
              "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "binary_sha256": binary_hash,
              "binary": str(args.binary.resolve()), "transport": "HTTP/1.1 JSON/base64, keep-alive",
              "model": "closed-loop, one outstanding request per producer, fresh server per case",
              "warmup_requests": args.warmup, "script_delay_ms": args.script_delay_ms, "cases": []}
    print("mode     bytes clients    ok/total      req/s   p50 ms   p95 ms   p99 ms   errors", flush=True)
    for mode in ("baseline", "script"):
        for size in args.sizes:
            for concurrency in args.concurrency:
                result = case(args, mode, size, concurrency)
                report["cases"].append(result)
                times = result["latency_ms_all"]
                print(f"{mode:8} {size:6} {concurrency:7} {result['successes']:5}/{args.requests:<5} "
                      f"{result['requests_per_second']:9.1f} {times['p50']:8.3f} "
                      f"{times['p95']:8.3f} {times['p99']:8.3f} {result['errors']}", flush=True)
                if args.output:
                    args.output.write_text(json.dumps(report, indent=2) + "\n")
    # A fast fail-open is a failed benchmark, not a latency improvement.
    return int(any(r["errors"] or r["warmup_errors"] or r["backend_errors"]
                   or r.get("backend_rejected", 0) or r.get("suspended", False)
                   or (r["mode"] == "script" and r["backend_runs"] != args.requests)
                   for r in report["cases"]))


if __name__ == "__main__":
    raise SystemExit(main())

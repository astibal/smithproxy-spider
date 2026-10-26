"""Verify measurement accounting independently of Spider and its workers."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from webhook_benchmark import batch, latency, percentile


class BenchmarkTest(unittest.TestCase):
    def test_percentiles(self):
        self.assertIsNone(percentile([], 95))
        self.assertEqual(latency([4, 1, 3, 2]), {"p50": 2, "p95": 4, "p99": 4, "max": 4})

    def test_response_accounting(self):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            reply = {"action": "unchanged"}

            def log_message(self, *_):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                wire = json.dumps(self.reply).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(wire)))
                self.end_headers()
                self.wfile.write(wire)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/webhook"
            good = batch(url, 1, 7, 3, False)
            self.assertEqual(good["successes"], 7)
            self.assertEqual(good["errors"], {})
            failed = batch(url, 1, 7, 3, True)
            self.assertEqual(failed["errors"], {"unexpected_unchanged": 7})
            self.assertEqual(failed["successful_requests_per_second"], 0)
            self.assertIsNone(failed["latency_ms_success"]["p99"])
            Handler.reply = {"action": "replace", "content": "QQ=="}
            self.assertEqual(batch(url, 1, 7, 3, True)["successes"], 7)
            Handler.reply = {"action": "replace", "content": "wrong"}
            self.assertEqual(batch(url, 1, 7, 3, True)["errors"], {"incorrect_replacement": 7})
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()

import importlib.util
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from functools import partial
from pathlib import Path
from http.server import ThreadingHTTPServer


SCRIPT = Path(__file__).parents[1] / "tools" / "serve-frontend.py"
SPEC = importlib.util.spec_from_file_location("serve_frontend", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FrontendPrefixTests(unittest.TestCase):
    def test_serves_assets_under_prefix_and_injects_backend_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index.html").write_text(
                '<meta name="frontend-version" content="development">'
                '<script src="app.js"></script>', encoding="utf-8")
            (root / "app.js").write_text("ok", encoding="utf-8")
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                partial(MODULE.FrontendHandler, directory=directory,
                        base_path="/ws001/spider/",
                        backend_path="/ws001/spider-api/"))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = HTTPConnection("127.0.0.1", server.server_port)
                client.request("GET", "/ws001/spider/")
                response = client.getresponse()
                body = response.read().decode()
                self.assertEqual(200, response.status)
                self.assertIn('content="/ws001/spider-api/"', body)
                client.request("GET", "/ws001/spider/app.js")
                response = client.getresponse()
                self.assertEqual(b"ok", response.read())
                client.request("GET", "/app.js")
                self.assertEqual(404, client.getresponse().status)
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()

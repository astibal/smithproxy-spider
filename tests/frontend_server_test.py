"""Versioning tests; isolated temporary assets and localhost server."""
import importlib.util
import json
import tempfile
import threading
import unittest
from functools import partial
from pathlib import Path
from urllib.request import Request, urlopen

spec = importlib.util.spec_from_file_location(
    "frontend_server", Path(__file__).resolve().parents[1] / "tools/serve-frontend.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FrontendVersionTest(unittest.TestCase):
    def test_content_version_and_cache_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index.html").write_text(
                '<meta name="frontend-version" content="development">'
                '<link href="style.css"><script src="vendor/editor.js"></script>')
            (root / "style.css").write_text("body{color:red}")
            (root / "vendor").mkdir()
            (root / "vendor/editor.js").write_text("/* editor */")
            server = module.ThreadingHTTPServer(
                ("127.0.0.1", 0), partial(module.FrontendHandler, directory=directory))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                with urlopen(base + "/frontend-version.json") as response:
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    version = json.load(response)["version"]
                with urlopen(base + "/?ui=old") as response:
                    html = response.read().decode()
                    self.assertIn(f'content="{version}"', html)
                    self.assertIn(f'vendor/editor.js?v={version}', html)
                    self.assertIn(f'style.css?v={version}', html)
                request = Request(base + "/style.css?v=" + version, headers={
                    "If-Modified-Since": "Wed, 31 Dec 2099 23:59:59 GMT"})
                with urlopen(request) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                with urlopen(Request(base + "/index.html", method="HEAD")) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"")
                (root / "vendor/editor.js").write_text("/* changed without a commit */")
                with urlopen(base + "/frontend-version.json") as response:
                    newer = json.load(response)["version"]
                self.assertNotEqual(version, newer)
                self.assertEqual(newer, module.frontend_version(directory))
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == "__main__":
    unittest.main()

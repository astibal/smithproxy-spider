#!/usr/bin/env python3
"""Lab frontend server: content-based UI versions, no stale browser assets."""
import argparse
import hashlib
import io
import json
import re
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


def frontend_version(directory):
    root = Path(directory)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in {".html", ".css", ".js"}:
            digest.update(path.relative_to(root).as_posix().encode() + b"\0")
            digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()[:12]


def normalize_base_path(value):
    value = "/" + value.strip("/")
    return "/" if value == "/" else value + "/"


def versioned_index(directory, version, backend_path=""):
    html = (Path(directory) / "index.html").read_text()
    html = html.replace('name="frontend-version" content="development"',
                        f'name="frontend-version" content="{version}"')
    if backend_path:
        html = html.replace(
            '<meta name="frontend-version"',
            f'<meta name="spider-backend-path" content="{backend_path}">'
            '<meta name="frontend-version"',
        )
    return re.sub(r'((?:src|href)=")([^":?]+\.(?:js|css))(")',
                  lambda m: f'{m[1]}{m[2]}?v={version}{m[3]}', html).encode()


class FrontendHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, base_path="/", backend_path="", **kwargs):
        self.base_path = normalize_base_path(base_path)
        self.backend_path = backend_path
        super().__init__(*args, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_head(self):
        path = urlsplit(self.path).path
        prefix = self.base_path.rstrip("/")
        if self.base_path != "/":
            if path == prefix:
                self.send_response(308)
                self.send_header("Location", self.base_path)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            if not path.startswith(self.base_path):
                self.send_error(404)
                return None
            path = "/" + path[len(self.base_path):]
            query = urlsplit(self.path).query
            self.path = path + (("?" + query) if query else "")
        if path in {"/", "/index.html", "/frontend-version.json"}:
            version = frontend_version(self.directory)
            if path == "/frontend-version.json":
                body = json.dumps({"version": version}).encode()
                content_type = "application/json"
            else:
                body = versioned_index(self.directory, version, self.backend_path)
                content_type = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return io.BytesIO(body)
        # Avoid 304 responses based only on timestamps after dirty source copies.
        for header in ("If-Modified-Since", "If-None-Match"):
            if header in self.headers:
                del self.headers[header]
        return super().send_head()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--directory", required=True)
    parser.add_argument("--base-path", default="/",
                        help="URL prefix used when served behind a reverse proxy")
    parser.add_argument("--backend-path", default="",
                        help="same-origin path of the Spider API")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.bind, args.port),
                                partial(FrontendHandler, directory=args.directory,
                                        base_path=args.base_path,
                                        backend_path=args.backend_path))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

#!/usr/bin/env python3
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_KEY = "integration-key"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        if self.path == "/api/authorize":
            if body.get("access_key") != API_KEY:
                self.reply(403, {"error": "access denied"})
                return
            self.reply(200, {"auth_token": "auth", "csrf_token": "csrf"})
            return
        if self.path == "/api/webhook/register":
            if body.get("auth_token") != "auth" or body.get("csrf_token") != "csrf":
                self.reply(401, {"error": "access denied"})
                return
            callback = body["params"]["rande_url"]
            self.reply(200, {"status": "accepted"})
            threading.Thread(target=send_ping, args=(callback,), daemon=True).start()
            return
        self.reply(404, {"error": "not found"})

def send_ping(callback):
    payload = json.dumps({
        "action": "ping", "source": "fake-smithproxy",
        "type": "proxy", "instance": "integration", "proxies": []
    }).encode()
    request = urllib.request.Request(callback, data=payload, headers={"Content-Type": "application/json"})
    for _ in range(30):
        try:
            urllib.request.urlopen(request, timeout=1).read()
            print(f"callback delivered: {callback}", flush=True)
            return
        except OSError:
            time.sleep(0.1)
    print(f"callback failed: {callback}", flush=True)

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 15555), Handler).serve_forever()

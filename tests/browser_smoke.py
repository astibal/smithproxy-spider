"""Run GUI smoke against an ephemeral local frontend, never the user's tab.

Requires Node + Playwright (NODE_PATH supported) and a Chromium installation
(CHROMIUM_PATH supported). All backend requests are mocked by the GUI suite.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import threading
from functools import partial

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeat', type=int, choices=range(1, 11), default=1)
    arguments = parser.parse_args()
    spec = importlib.util.spec_from_file_location('frontend', ROOT / 'tools/serve-frontend.py')
    frontend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(frontend)

    class QuietHandler(frontend.FrontendHandler):
        def log_message(self, *args):
            pass

    server = frontend.ThreadingHTTPServer(
        ('127.0.0.1', 0), partial(QuietHandler, directory=str(ROOT / 'frontend')))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    environment = os.environ.copy()
    environment['SPIDER_TEST_FRONTEND_URL'] = f'http://127.0.0.1:{server.server_port}'
    try:
        for attempt in range(arguments.repeat):
            print(f'Browser smoke {attempt + 1}/{arguments.repeat}', flush=True)
            result = subprocess.run(['node', 'tests/inspection_gui.cjs'], cwd=ROOT,
                                    env=environment, timeout=180)
            if result.returncode:
                return result.returncode
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    raise SystemExit(main())

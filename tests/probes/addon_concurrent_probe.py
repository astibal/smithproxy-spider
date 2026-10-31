#!/usr/bin/env python3
"""Record clean-room observations of mitmproxy.script.concurrent."""

import argparse
import importlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

from addon_concurrent_contract import collect


def observations():
    script_module = importlib.import_module("mitmproxy.script")
    implementation_module = importlib.import_module("mitmproxy.script.concurrent")
    return {
        "reference": "mitmproxy 12.3.1",
        **collect(script_module, implementation_module),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", type=Path)
    args = parser.parse_args()
    actual = observations()
    if args.expect:
        expected = json.loads(args.expect.read_text())
        if actual != expected:
            print(json.dumps(actual, indent=2, sort_keys=True))
            raise SystemExit("concurrent observations differ from the corpus")
    else:
        print(json.dumps(actual, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

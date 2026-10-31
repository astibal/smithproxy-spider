#!/usr/bin/env python3
"""Record public DNS domain-name behavior from the reference runtime."""

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

from addon_dns_domain_names_contract import collect
from mitmproxy.net.dns import domain_names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", type=Path)
    arguments = parser.parse_args()
    actual = {
        "reference": "mitmproxy 12.3.1",
        "domain_names": collect(domain_names),
    }
    if arguments.expect is not None:
        expected = json.loads(arguments.expect.read_text())
        if actual != expected:
            print(json.dumps(actual, indent=2, sort_keys=True))
            raise SystemExit("DNS domain-name observations differ from the corpus")
        return
    print(json.dumps(actual, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

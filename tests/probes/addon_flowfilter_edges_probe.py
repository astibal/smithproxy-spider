"""Record adversarial public flow-filter parsing from an isolated reference."""

import argparse
import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from addon_flowfilter_edges_contract import collect
from mitmproxy import flowfilter


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    arguments = parser.parse_args()

    result = {
        "reference": "mitmproxy 12.3.1",
        "cases": collect(flowfilter),
    }
    if arguments.expect:
        expected = json.loads(Path(arguments.expect).read_text())
        if result != expected:
            raise AssertionError("Reference flow-filter behavior changed")

    rendered = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()

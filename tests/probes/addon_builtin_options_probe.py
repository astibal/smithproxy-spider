"""Record the public default option inventory from mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path

from mitmproxy import optmanager
from mitmproxy.options import Options


def normalized(value):
    if isinstance(value, tuple):
        return [normalized(item) for item in value]
    if isinstance(value, list):
        return [normalized(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalized(item) for key, item in value.items()}
    return value


def collect():
    options = Options()
    inventory = {}
    for name, option in sorted(options.items()):
        inventory[name] = {
            "typespec": str(option.typespec),
            "default": normalized(options.default(name)),
            "value": normalized(getattr(options, name)),
            "choices": normalized(option.choices),
            "changed": options.has_changed(name),
        }

    configured = Options(listen_port=9000, http2=False, mode=["socks5"])
    return {
        "reference": "mitmproxy 12.3.1",
        "empty_optmanager_keys": sorted(optmanager.OptManager().keys()),
        "inventory": inventory,
        "configured": {
            "listen_port": configured.listen_port,
            "http2": configured.http2,
            "mode": configured.mode,
            "changed": {
                name: configured.has_changed(name)
                for name in ("listen_port", "http2", "mode", "server")
            },
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()
    result = collect()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference built-in option inventory changed")
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()

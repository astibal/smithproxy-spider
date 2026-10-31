"""Argument-parser option behavior shared by reference and adapter tests."""

import argparse
from collections.abc import Sequence


def collect(manager_type):
    options = manager_type()
    options.add_option("enabled", bool, False, "Enable the feature")
    options.add_option("count", int, 1, "Count")
    options.add_option("port", int | None, None, "Port")
    options.add_option("label", str, "default", "Label")
    options.add_option("maybe", str | None, None, "Optional label")
    options.add_option("names", Sequence[str], [], "Names")
    options.add_option(
        "http2_ping_keepalive",
        int,
        58,
        "Ping interval",
        choices=[10, 20],
    )

    parser = argparse.ArgumentParser(add_help=False)
    options.make_parser(parser, "enabled")
    options.make_parser(parser, "count")
    options.make_parser(parser, "port")
    options.make_parser(parser, "label")
    options.make_parser(parser, "maybe")
    options.make_parser(parser, "names")
    options.make_parser(
        parser,
        "http2_ping_keepalive",
        metavar="SECONDS",
        short="p",
    )
    before_unknown = len(parser._actions)
    unknown_result = options.make_parser(parser, "unknown")

    unsupported = []
    for name, typespec, default in (
        ("floating", float, 1.0),
        ("binary", bytes, b"value"),
        ("integer_names", Sequence[int], []),
        ("optional_enabled", bool | None, None),
    ):
        options.add_option(name, typespec, default, "Unsupported parser type")
        action_count = len(parser._actions)
        try:
            options.make_parser(parser, name)
        except Exception as error:
            unsupported.append({
                "name": name,
                "error": type(error).__name__,
                "message": str(error),
                "added_action": len(parser._actions) != action_count,
            })
        else:
            unsupported.append({
                "name": name,
                "error": None,
                "message": None,
                "added_action": len(parser._actions) != action_count,
            })

    actions = []
    for action in parser._actions:
        actions.append({
            "options": list(action.option_strings),
            "kind": type(action).__name__,
            "dest": action.dest,
            "type": getattr(action.type, "__name__", None),
            "metavar": action.metavar,
            "help": action.help,
            "default": action.default,
        })

    cases = []
    for arguments in (
        [],
        ["--enabled"],
        ["--no-enabled"],
        ["--count", "3", "--port", "8443", "--label", "test"],
        ["--maybe", "value", "--names", "one", "--names", "two"],
        ["-p", "20"],
    ):
        cases.append({
            "arguments": arguments,
            "parsed": vars(parser.parse_args(arguments)),
        })

    return {
        "actions": actions,
        "cases": cases,
        "unknown_returned_none": unknown_result is None,
        "unknown_added_action": len(parser._actions) != before_unknown,
        "unsupported": unsupported,
    }

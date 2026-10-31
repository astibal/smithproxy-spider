"""Command registration edge cases shared by reference and adapter tests."""

import inspect
import re
from types import SimpleNamespace


def collect(command):
    observations = {}

    def record(name, operation):
        try:
            observations[name] = {"value": operation()}
        except Exception as error:
            message = re.sub(r"0x[0-9a-fA-F]+", "0xADDRESS", str(error))
            observations[name] = {
                "error": type(error).__name__,
                "message": message,
            }

    def original(value: str = "default") -> str:
        """Keep public metadata."""
        return value

    decorated = command.command()(original)
    record("decorator/default", lambda: {
        "same_object": decorated is original,
        "name": decorated.__name__,
        "doc": decorated.__doc__,
        "annotations": {
            name: getattr(annotation, "__name__", str(annotation))
            for name, annotation in decorated.__annotations__.items()
        },
        "signature": str(inspect.signature(decorated)),
        "command_name": decorated.command_name,
        "has_wrapped": hasattr(decorated, "__wrapped__"),
        "call": decorated("value"),
    })

    explicitly_named = command.command("edge.explicit")(original)
    record("decorator/explicit", lambda: {
        "same_object": explicitly_named is original,
        "command_name": explicitly_named.command_name,
        "original_command_name": getattr(original, "command_name", None),
        "call": explicitly_named(),
    })

    manager = command.CommandManager(SimpleNamespace())

    class DuplicateMethods:
        @command.command("edge.duplicate")
        def alpha(self) -> str:
            return "alpha"

        @command.command("edge.duplicate")
        def zeta(self) -> str:
            return "zeta"

        @command.command()
        def implicit(self) -> str:
            return "implicit"

    duplicate = DuplicateMethods()
    record("collect/duplicate_methods", lambda: manager.collect_commands(duplicate))
    record("call/duplicate_methods", lambda: manager.call("edge.duplicate"))
    record("call/implicit_name", lambda: manager.call("implicit"))
    record("collect/same_owner_again", lambda: manager.collect_commands(duplicate))
    record("call/same_owner_again", lambda: manager.call("edge.duplicate"))

    class FirstOwner:
        @command.command("edge.owner")
        def owned(self) -> str:
            return "first"

    class SecondOwner:
        @command.command("edge.owner")
        def owned(self) -> str:
            return "second"

    first = FirstOwner()
    second = SecondOwner()
    record("collect/first_owner", lambda: manager.collect_commands(first))
    record("call/first_owner", lambda: manager.call("edge.owner"))
    record("collect/second_owner", lambda: manager.collect_commands(second))
    record("call/second_owner", lambda: manager.call("edge.owner"))
    record("collect/first_owner_again", lambda: manager.collect_commands(first))
    record("call/first_owner_again", lambda: manager.call("edge.owner"))

    def valid_replacement() -> str:
        return "valid replacement"

    def invalid_replacement(value: float) -> str:
        return str(value)

    record(
        "replace/direct_valid",
        lambda: manager.add("edge.owner", valid_replacement),
    )
    record("call/direct_valid", lambda: manager.call("edge.owner"))
    record(
        "replace/direct_invalid",
        lambda: manager.add("edge.owner", invalid_replacement),
    )
    record("call/after_direct_invalid", lambda: manager.call("edge.owner"))

    class InvalidCollectedReplacement:
        @command.command("edge.owner")
        def owned(self, value: float) -> str:
            return str(value)

    record(
        "replace/collected_invalid",
        lambda: manager.collect_commands(InvalidCollectedReplacement()),
    )
    record("call/after_collected_invalid", lambda: manager.call("edge.owner"))

    class UnusualNames:
        @command.command("")
        def empty(self) -> str:
            return "empty"

        @command.command("příkaz.čaj")
        def unicode(self) -> str:
            return "čaj"

    record("collect/unusual_names", lambda: manager.collect_commands(UnusualNames()))
    record("call/empty_name", lambda: manager.call(""))
    record("call/unicode_name", lambda: manager.call("příkaz.čaj"))
    record("registry/names", lambda: sorted(manager.commands))

    return observations

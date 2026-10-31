"""Saved-flow I/O for the clean-room addon facade."""

from pathlib import Path

from addon_exceptions import FlowReadException
from addon_flow import Flow
import addon_flowfilter
import addon_tnetstring as tnetstring


class FlowWriter:
    def __init__(self, fo):
        self.fo = fo

    def add(self, flow):
        tnetstring.dump(flow.get_state(), self.fo)


class FilteredFlowWriter(FlowWriter):
    def __init__(self, fo, flt):
        super().__init__(fo)
        self.flt = flt

    def add(self, flow):
        if self.flt is None or addon_flowfilter.match(self.flt, flow):
            super().add(flow)


class FlowReader:
    def __init__(self, fo):
        self.fo = fo

    def stream(self):
        while True:
            first = self.fo.read(1)
            if not first:
                return
            try:
                self.fo.seek(-1, 1)
            except (AttributeError, OSError):
                source = _PrefixedReader(first, self.fo)
            else:
                source = self.fo

            try:
                state = tnetstring.load(source)
            except (ValueError, TypeError) as error:
                raise FlowReadException("Invalid data format.") from error
            try:
                if not isinstance(state, dict):
                    raise ValueError(f"Invalid flow: loaded={state!r}")
                yield Flow.from_state(state)
            except (AssertionError, KeyError, TypeError, ValueError) as error:
                if isinstance(error, ValueError) and str(error).startswith("Invalid flow:"):
                    failure = error
                else:
                    failure = ValueError(f"Invalid flow: {error}")
                raise FlowReadException(str(failure)) from error


class _PrefixedReader:
    """Expose one consumed byte in front of a non-seekable input stream."""

    def __init__(self, prefix, source):
        self.prefix = prefix
        self.source = source

    def read(self, size=-1):
        if not self.prefix:
            return self.source.read(size)
        if size < 0:
            result = self.prefix + self.source.read()
            self.prefix = b""
            return result
        result = self.prefix[:size]
        self.prefix = self.prefix[size:]
        if len(result) < size:
            result += self.source.read(size - len(result))
        return result


def read_flows_from_paths(paths):
    flows = []
    for path in paths:
        try:
            with Path(path).open("rb") as input_file:
                flows.extend(FlowReader(input_file).stream())
        except FileNotFoundError:
            raise FlowReadException("No such file or directory") from None
        except OSError as error:
            message = error.strerror or str(error)
            raise FlowReadException(message) from None
    return flows


__all__ = ("FlowWriter", "FlowReader", "FilteredFlowWriter", "read_flows_from_paths")

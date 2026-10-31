"""Public addon exception hierarchy without proxy implementation details."""


class MitmproxyException(Exception):
    """Base class for public compatibility errors."""


class FlowReadException(MitmproxyException):
    """A serialized flow cannot be restored."""


class AddonHalt(MitmproxyException):
    """An addon deliberately stops the current lifecycle operation."""

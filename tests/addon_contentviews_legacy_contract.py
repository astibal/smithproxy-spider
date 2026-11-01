"""Shared black-box observations for the legacy content-view bridge."""

from typing import get_args
import warnings


def warning_records(callback):
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        value = callback()
    return value, [
        {
            "type": type(item.message).__name__,
            "message": str(item.message),
        }
        for item in captured
    ]


def collect(contentviews):
    class LegacyProbe(contentviews.View):
        name = "Spider Legacy Probe"

        def __init__(self):
            self.metadata = None

        def __call__(self, data, **metadata):
            self.metadata = metadata
            return "legacy description", iter([
                [("header", "first "), ("text", data)],
                [("error", "tail")],
            ])

        def render_priority(self, data, **metadata):
            return 7

    class DefaultPriorityProbe(contentviews.View):
        name = "Spider Default Priority Probe"

        def __call__(self, data, **metadata):
            return "default", iter([])

    legacy = LegacyProbe()
    _, add_warnings = warning_records(lambda: contentviews.add(legacy))
    wrapped = contentviews.registry.get("spider legacy probe")

    flow = object()
    http_message = object()
    metadata = contentviews.Metadata(
        flow=flow,
        content_type="text/plain",
        http_message=http_message,
        original_data=b"original",
    )
    prettified = wrapped.prettify(b"payload", metadata)
    priority = wrapped.render_priority(b"payload", metadata)
    found, get_warnings = warning_records(
        lambda: contentviews.get("SPIDER LEGACY PROBE")
    )
    remove_result, remove_warnings = warning_records(
        lambda: contentviews.remove(legacy)
    )

    try:
        contentviews.View()
    except Exception as error:
        view_constructor = {
            "type": type(error).__name__,
            "message": str(error),
        }
    else:
        view_constructor = {"type": None, "message": None}

    default_priority = DefaultPriorityProbe().render_priority(b"payload")
    return {
        "surface": {
            "view_module": contentviews.View.__module__,
            "legacy_module": contentviews.LegacyContentview.__module__,
            "legacy_metaclass": type(contentviews.LegacyContentview).__name__,
            "alias_type": type(contentviews.ContentviewMessage).__name__,
            "alias_name": contentviews.ContentviewMessage.__name__,
            "alias_module": contentviews.ContentviewMessage.__module__,
            "alias_members": [
                member.__name__
                for member in get_args(contentviews.ContentviewMessage.__value__)
            ],
            "base_identity": contentviews.base.View is contentviews.View,
            "compat_identity": (
                contentviews._compat.LegacyContentview
                is contentviews.LegacyContentview
            ),
            "utils_identity": (
                contentviews._utils.ContentviewMessage
                is contentviews.ContentviewMessage
            ),
        },
        "view_constructor": view_constructor,
        "default_priority": default_priority,
        "add_warnings": add_warnings,
        "wrapper": {
            "type": type(wrapped).__name__,
            "module": type(wrapped).__module__,
            "contentview_identity": wrapped.contentview is legacy,
            "name": wrapped.name,
            "syntax_highlight": wrapped.syntax_highlight,
            "prettified": prettified,
            "priority": priority,
        },
        "metadata": {
            "keys": sorted(legacy.metadata),
            "content_type": legacy.metadata.get("content_type"),
            "flow_identity": legacy.metadata.get("flow") is flow,
            "http_message_identity": (
                legacy.metadata.get("http_message") is http_message
            ),
        },
        "get": {
            "identity": found is wrapped,
            "warnings": get_warnings,
        },
        "remove": {
            "result": remove_result,
            "still_registered": (
                contentviews.registry.get("spider legacy probe") is wrapped
            ),
            "warnings": remove_warnings,
        },
    }

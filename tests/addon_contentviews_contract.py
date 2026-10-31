"""Deterministic observations of the public mitmproxy 12 content-view API."""

from dataclasses import asdict


def collect(contentviews):
    class SpiderProbeDefault(contentviews.Contentview):
        def prettify(self, data, metadata):
            return data.swapcase().decode("ascii")

        def render_priority(self, data, metadata):
            return 10000 if metadata.content_type == "text/x-spider-probe" else 0

    class SpiderProbeInteractive(contentviews.InteractiveContentview):
        syntax_highlight = "yaml"

        def prettify(self, data, metadata):
            return "value: " + data.decode("ascii")

        def render_priority(self, data, metadata):
            return 9999

        def reencode(self, prettified, metadata):
            return prettified.removeprefix("value: ").encode("ascii")

    metadata = contentviews.Metadata(
        content_type="text/x-spider-probe",
        original_data=b"original",
    )
    default = SpiderProbeDefault()
    interactive = SpiderProbeInteractive()

    result = {
        "all": list(contentviews.__all__),
        "result": {
            "value": vars(contentviews.ContentviewResult(
                "rendered", "yaml", "Probe", "probe description"
            )),
            "match_args": list(contentviews.ContentviewResult.__match_args__),
            "equal": contentviews.ContentviewResult(
                "rendered", "yaml", "Probe", "probe description"
            ) == contentviews.ContentviewResult(
                "rendered", "yaml", "Probe", "probe description"
            ),
        },
        "metadata": {
            key: value.hex() if isinstance(value, bytes) else value
            for key, value in asdict(metadata).items()
        },
        "default": {
            "name": default.name,
            "syntax_highlight": default.syntax_highlight,
            "priority": default.render_priority(b"abc", metadata),
            "prettified": default.prettify(b"AbC", metadata),
            "contentview": isinstance(default, contentviews.Contentview),
            "interactive": isinstance(default, contentviews.InteractiveContentview),
        },
        "interactive": {
            "name": interactive.name,
            "syntax_highlight": interactive.syntax_highlight,
            "prettified": interactive.prettify(b"abc", metadata),
            "reencoded": interactive.reencode("value: xyz", metadata).hex(),
            "contentview": isinstance(interactive, contentviews.Contentview),
            "interactive": isinstance(interactive, contentviews.InteractiveContentview),
        },
    }

    contentviews.add(SpiderProbeDefault)
    first = contentviews.registry.get("spiderprobedefault")
    contentviews.add(SpiderProbeDefault)
    second = contentviews.registry.get("SPIDERPROBEDEFAULT")
    contentviews.add(interactive)

    class SpiderProbeReplacement(SpiderProbeDefault):
        name = "SpiderProbeDefault"

    replacement = SpiderProbeReplacement()
    contentviews.add(replacement)
    selected = contentviews.registry.get_view(b"abc", metadata, "auto")
    requested = contentviews.registry.get_view(
        b"abc", metadata, "SpiderProbeInteractive"
    )
    fallback = contentviews.registry.get_view(b"abc", metadata, "missing-probe-view")

    result["registry"] = {
        "class_reinstantiated": first is not second,
        "duplicate_replaced": contentviews.registry.get("spiderprobedefault") is replacement,
        "instance_preserved": contentviews.registry.get("spiderprobeinteractive") is interactive,
        "available": [
            name for name in contentviews.registry.available_views()
            if name.startswith("spiderprobe")
        ],
        "auto": type(selected).__name__,
        "requested": type(requested).__name__,
        "missing_falls_back": type(fallback).__name__,
    }

    failures = {}
    for name, value in (("none", None), ("integer", 42), ("plain_class", object)):
        try:
            contentviews.add(value)
        except Exception as error:
            failures[name] = {
                "type": type(error).__name__,
                "message": str(error),
            }
        else:
            failures[name] = {"type": None, "message": None}
    result["failures"] = failures
    return result

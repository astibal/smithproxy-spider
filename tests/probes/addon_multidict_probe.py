"""Record direct multidict behavior through the public API."""

import json

from mitmproxy.coretypes.multidict import MultiDict, MultiDictView
from mitmproxy.net.http.cookies import CookieAttrs


def outcome(callback):
    try:
        value = callback()
        return {"ok": True, "type": type(value).__name__, "repr": repr(value)}
    except Exception as error:
        return {
            "ok": False,
            "type": type(error).__name__,
            "message": str(error),
        }


def snapshot(value):
    result = {
        "type": type(value).__name__,
        "repr": repr(value),
        "fields": repr(value.fields),
        "items": repr(list(value.items())),
        "items_multi": repr(list(value.items(multi=True))),
        "keys": repr(list(value.keys())),
        "keys_multi": repr(list(value.keys(multi=True))),
        "values": repr(list(value.values())),
        "values_multi": repr(list(value.values(multi=True))),
        "length": len(value),
    }
    if hasattr(value, "get_state"):
        result["state"] = repr(value.get_state())
    return result


owned = MultiDict([("a", "one"), ("a", "two"), ("b", "three")])
cases = {
    "owned": snapshot(owned),
    "owned-copy": snapshot(owned.copy()),
    "owned-missing-get": outcome(lambda: owned["missing"]),
    "owned-missing-delete": outcome(lambda: owned.__delitem__("missing")),
    "owned-other-equality": owned == {"a": "one"},
}

restored = MultiDict()
restored.set_state(owned.get_state())
cases["owned-set-state"] = snapshot(restored)
cases["owned-from-state"] = snapshot(MultiDict.from_state(owned.get_state()))

storage = {"fields": (("a", "one"), ("a", "two"))}
view = MultiDictView(
    lambda: storage["fields"],
    lambda fields: storage.__setitem__("fields", fields),
)
cases["view"] = snapshot(view)
cases["view-repr"] = repr(view)
view.clear()
cases["view-cleared"] = snapshot(view)

attributes = CookieAttrs([
    ("Path", "/first"),
    ("path", "/second"),
    ("Secure", None),
])
cases["cookie-attrs"] = snapshot(attributes)
cases["cookie-last-wins"] = attributes["PATH"]
cases["cookie-copy"] = snapshot(attributes.copy())

print(json.dumps({"reference": "12.3.1", "cases": cases}, sort_keys=True))

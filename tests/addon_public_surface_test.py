"""Public data exports and exception hierarchy against the v12 corpus."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from addon_modules import compatibility_modules
from addon_loader import compatibility_imports
from addon_manager import AddonManager
from addon_commands import CommandManager
from addon_options import Loader, OptManager


CLASS_NAMES = (
    "Client", "Connection", "DNSFlow", "DNSMessage", "Error", "Flow",
    "HTTPFlow", "Headers", "Message", "Request", "Response", "Server",
    "TCPFlow", "TCPMessage", "UDPFlow", "UDPMessage", "WebSocketData",
    "WebSocketMessage",
)


def normalized(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, tuple):
        return {"tuple": [normalized(item) for item in value]}
    if isinstance(value, list):
        return [normalized(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalized(item) for key, item in value.items()}
    return value


class PublicSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(
            (ROOT / "tests/corpus/addon_public_surface_v12.json").read_text()
        )

    def test_http_data_objects_match_reference_state_contract(self):
        with compatibility_imports(compatibility_modules()):
            from mitmproxy import http

            headers = http.Headers([(b"X-A", b"one"), (b"X-A", b"two")])
            values = [
                http.MessageData(b"HTTP/2.0", headers, b"body", None, 1.5, None),
                http.RequestData(
                    b"HTTP/2.0", headers, b"body", None, 1.5, 2.5,
                    "example.test", 443, b"GET", b"https", b"example.test", b"/x",
                ),
                http.ResponseData(
                    b"HTTP/2.0", headers, b"body", None, 1.5, 2.5, 201, b"Created",
                ),
            ]
            for value in values:
                with self.subTest(type=type(value).__name__):
                    expected = self.corpus["data"][type(value).__name__]
                    copied = value.copy()
                    partial = value.copy()
                    partial.set_state({"headers": ((b"Y", b"changed"),), "unknown": 1})
                    actual = {
                        "state": normalized(value.get_state()),
                        "roundtrip": normalized(type(value).from_state(
                            value.get_state()).get_state()),
                        "copy_state": normalized(copied.get_state()),
                        "copy_has_independent_headers": copied.headers is not value.headers,
                        "partial_state": normalized(partial.get_state()),
                    }
                    self.assertEqual(actual, expected)

    def test_exception_hierarchy_and_options_import_match_reference(self):
        modules = compatibility_modules()
        with compatibility_imports(modules):
            from mitmproxy import addonmanager, connection, dns, exceptions, hooks, http
            from mitmproxy import optmanager, options

            self.assertEqual(options.Options.__module__, "addon_options")
            self.assertEqual(len(options.Options().keys()), 29)
            self.assertTrue(options.Options().http2)
            self.assertEqual(optmanager.OptManager().keys(), set())
            self.assertIs(http.encoding, modules["mitmproxy.net.encoding"])
            self.assertIs(http.multipart,
                          modules["mitmproxy.net.http.multipart"])
            self.assertIs(http.multidict,
                          modules["mitmproxy.coretypes.multidict"])
            self.assertIs(http.flow, modules["mitmproxy.flow"])
            self.assertIs(http.serializable,
                          modules["mitmproxy.coretypes.serializable"])
            self.assertIs(connection.certs, modules["mitmproxy.certs"])
            self.assertIs(connection.human, modules["mitmproxy.utils.human"])
            self.assertIs(connection.mode_specs,
                          modules["mitmproxy.proxy.mode_specs"])
            self.assertIs(connection.serializable,
                          modules["mitmproxy.coretypes.serializable"])
            self.assertIs(modules["mitmproxy.flow"].connection, connection)
            self.assertIs(modules["mitmproxy.flow"].serializable,
                          modules["mitmproxy.coretypes.serializable"])
            self.assertIs(addonmanager.AddonManager, AddonManager)
            self.assertIs(
                dns.domain_names,
                modules["mitmproxy.net.dns.domain_names"],
            )
            self.assertIs(dns.flow, modules["mitmproxy.flow"])
            self.assertIs(
                dns.https_records,
                modules["mitmproxy.net.dns.https_records"],
            )
            self.assertIs(
                dns.serializable,
                modules["mitmproxy.coretypes.serializable"],
            )
            self.assertEqual(set(hooks.all_hooks), {
                "add_log", "configure", "done", "running", "update"
            })
            self.assertEqual(options.CONF_DIR, "~/.mitmproxy")
            for name, expected in self.corpus["exceptions"].items():
                with self.subTest(exception=name):
                    value = getattr(exceptions, name)
                    actual_mro = [item.__name__ for item in value.__mro__]
                    self.assertEqual(actual_mro, expected["mro"])
                    self.assertEqual(str(value("example")), expected["message"])

    def test_canonical_module_aliases_match_reference(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_module_aliases_v12.json").read_text()
        )
        modules = compatibility_modules()
        roots = {
            "http": modules["mitmproxy.http"],
            "connection": modules["mitmproxy.connection"],
            "flow": modules["mitmproxy.flow"],
        }
        actual = {
            group: {
                name: getattr(getattr(roots[group], name), "__name__", None)
                for name in aliases
            }
            for group, aliases in corpus["aliases"].items()
        }
        self.assertEqual(corpus["reference"], "mitmproxy 12.3.1")
        self.assertEqual(actual, corpus["aliases"])

        expected_star_exports = corpus["star_exports"]
        actual_star_exports = {
            name: list(modules[name].__all__)
            for name in expected_star_exports
        }
        self.assertEqual(actual_star_exports, expected_star_exports)
        modules_without_all = set(modules) - set(expected_star_exports)
        for name in modules_without_all:
            with self.subTest(module=name):
                self.assertFalse(hasattr(modules[name], "__all__"))

    def test_core_class_public_surface_matches_reference_major(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_class_surface_v12.json").read_text()
        )
        self.assertEqual(corpus["reference"], "mitmproxy 12.3.1")
        modules = compatibility_modules()
        values = {
            "Client": modules["mitmproxy.connection"].Client,
            "Connection": modules["mitmproxy.connection"].Connection,
            "DNSFlow": modules["mitmproxy.dns"].DNSFlow,
            "DNSMessage": modules["mitmproxy.dns"].DNSMessage,
            "Error": modules["mitmproxy.flow"].Error,
            "Flow": modules["mitmproxy.flow"].Flow,
            "HTTPFlow": modules["mitmproxy.http"].HTTPFlow,
            "Headers": modules["mitmproxy.http"].Headers,
            "Message": modules["mitmproxy.http"].Message,
            "Request": modules["mitmproxy.http"].Request,
            "Response": modules["mitmproxy.http"].Response,
            "Server": modules["mitmproxy.connection"].Server,
            "TCPFlow": modules["mitmproxy.tcp"].TCPFlow,
            "TCPMessage": modules["mitmproxy.tcp"].TCPMessage,
            "UDPFlow": modules["mitmproxy.udp"].UDPFlow,
            "UDPMessage": modules["mitmproxy.udp"].UDPMessage,
            "WebSocketData": modules["mitmproxy.websocket"].WebSocketData,
            "WebSocketMessage": modules["mitmproxy.websocket"].WebSocketMessage,
        }
        self.assertEqual(tuple(sorted(values)), tuple(sorted(CLASS_NAMES)))
        actual = {
            name: sorted(attribute for attribute in dir(value)
                         if not attribute.startswith("_"))
            for name, value in values.items()
        }
        self.assertEqual(actual, corpus["classes"])

    def test_service_class_public_surface_matches_reference_major(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_service_surface_v12.json").read_text()
        )
        self.assertEqual(corpus["reference"], "mitmproxy 12.3.1")
        values = {
            "AddonManager": AddonManager,
            "CommandManager": CommandManager,
            "Loader": Loader,
            "OptManager": OptManager,
        }
        actual = {
            name: sorted(
                attribute
                for attribute in dir(value)
                if not attribute.startswith("_")
            )
            for name, value in values.items()
        }
        self.assertEqual(actual, corpus["classes"])


if __name__ == "__main__":
    unittest.main()

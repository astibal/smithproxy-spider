"""Execute the documented hook examples in real addon generations."""
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from addon_authentication import AuthenticationAddonAdapter
from addon_native import NativeAddonAdapter
from addon_runtime import AddonGeneration


class HookExamplesTests(unittest.IsolatedAsyncioTestCase):
    async def load_example(self, name, hooks=NativeAddonAdapter.HOOKS):
        source = (ROOT / "examples" / "hooks" / name).read_text()
        generation = AddonGeneration(source, hooks)
        await generation.start()
        self.addAsyncCleanup(generation.close)
        return generation

    async def call(self, generation, name, data):
        failures = await generation.dispatch(name, data)
        self.assertFalse(failures, failures)

    async def test_tcp_tls(self):
        generation = await self.load_example("tcp_tls.py")
        conn = SimpleNamespace(sni="example.test", error="test failure")
        data = SimpleNamespace(conn=conn, client_hello=SimpleNamespace(sni="example.test"))

        await self.call(generation, "tls_clienthello", data)
        await self.call(generation, "tls_start_server", data)
        await self.call(generation, "tls_established_server", data)
        await self.call(generation, "tls_failed_server", data)

        self.assertEqual(conn.alpn_offers, [b"http/1.1"])
        self.assertEqual(conn.cipher_list, ["ECDHE+AESGCM"])

    async def test_quic(self):
        generation = await self.load_example("quic.py")
        data = SimpleNamespace(
            conn=SimpleNamespace(sni="example.test", transport_protocol="udp", error="test failure"),
            settings=SimpleNamespace(),
        )

        await self.call(generation, "quic_start_server", data)
        await self.call(generation, "tls_established_server", data)
        await self.call(generation, "tls_failed_server", data)

        self.assertEqual(data.settings.alpn_protocols, ["h3"])
        self.assertEqual(data.settings.cipher_suites, [0x1301])

    async def test_connect(self):
        generation = await self.load_example("connect.py")
        flow = SimpleNamespace(request=SimpleNamespace(host="blocked.example"), response=None)

        await self.call(generation, "http_connect", flow)
        self.assertEqual(flow.response.status_code, 403)
        await self.call(generation, "http_connected", flow)
        await self.call(generation, "http_connect_error", flow)
        await self.call(generation, "server_connected", SimpleNamespace(
            server=SimpleNamespace(peername=("192.0.2.1", 443)),
        ))

    async def test_starttls_observer(self):
        generation = await self.load_example("starttls.py")
        conn = SimpleNamespace(id="same-tcp-connection", tls_version="TLSv1.3")

        await self.call(generation, "server_connected", SimpleNamespace(
            server=SimpleNamespace(peername=("192.0.2.1", 25)),
        ))
        for hook in ("tls_start_server", "tls_start_client",
                     "tls_established_server", "tls_established_client"):
            await self.call(generation, hook, SimpleNamespace(conn=conn))

    async def test_authentication_never_upgrades_aaa(self):
        generation = await self.load_example("authentication.py", AuthenticationAddonAdapter.HOOKS)

        for username, accepted, expected in (("blocked", True, False),
                                             ("allowed", False, False),
                                             ("allowed", True, True)):
            data = SimpleNamespace(username=username, valid=accepted)
            await self.call(generation, "socks5_auth", data)
            self.assertEqual(data.valid, expected)

    def test_editor_examples_are_current(self):
        subprocess.run([sys.executable, str(ROOT / "tools/generate-hook-examples.py"), "--check"],
                       check=True)


if __name__ == "__main__":
    unittest.main()

"""Guard upstream rerouting behavior observed in mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus'


class RerouteContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = CORPUS / 'addon_reroute_v12.json'
        cls.corpus = json.loads(path.read_text())

    def test_reroute_in_either_request_hook_selects_new_upstream(self):
        self.assertEqual(self.corpus['original_contacts'], 0)
        self.assertEqual(
            [item['path'] for item in self.corpus['destination_requests']],
            ['/headers', '/request'],
        )
        for item in self.corpus['destination_requests']:
            self.assertEqual(item['host'], '127.0.0.1:destination')

    def test_reroute_updates_flow_and_host_header_atomically(self):
        hooks_by_path = {'/headers': [], '/request': []}
        for hook in self.corpus['hooks']:
            hooks_by_path[hook['path']].append(hook)

        for path, hooks in hooks_by_path.items():
            with self.subTest(path=path):
                changed = [
                    hook for hook in hooks
                    if hook['port'] == 'destination'
                ]
                self.assertTrue(changed)
                for hook in changed:
                    self.assertEqual(
                        hook['host_header'],
                        '127.0.0.1:destination',
                    )
                self.assertEqual(hooks[-1]['hook'], 'response')

        self.assertEqual(
            hooks_by_path['/headers'][1]['hook'],
            'requestheaders-after',
        )
        self.assertEqual(
            hooks_by_path['/request'][2]['hook'],
            'request-after',
        )

    def test_clients_receive_response_from_selected_destination(self):
        for path, response in self.corpus['clients'].items():
            with self.subTest(path=path):
                self.assertEqual(response['status_line'], 'HTTP/1.1 200 OK')
                self.assertEqual(response['body'], path)


if __name__ == '__main__':
    unittest.main()

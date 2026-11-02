"""Transient authentication policy through the real packaged worker."""
import unittest
from native_lifecycle_test import Worker


def observation(status='accepted'):
    return {'version': 1, 'protocol': 'socks5', 'username': 'test-user',
            'password': 'DO-NOT-RETAIN', 'status': status, 'identity': 'test-user',
            'groups': ['test-group'], 'peer': {'host': '127.0.0.1', 'port': '12345'}}


class AuthenticationTests(unittest.TestCase):
    def worker(self, source):
        worker = Worker(source)
        self.addCleanup(worker.close)
        self.assertTrue(worker.ready.get('ready'), worker.ready)
        return worker

    def test_persistent_policy_and_no_payload_api(self):
        worker = self.worker('''
def init(api, state):
    return {'calls': 0}
def main(api, state):
    assert api.phase == 'authentication'
    assert not hasattr(api, 'message')
    assert api.auth.groups == ('test-group',)
    state['calls'] += 1
    api.auth.allowed = state['calls'] == 1
    print(api.auth.password)
    state['secret'] = api.auth.password
def exit(api, state):
    print(state['secret'])
    raise ValueError(state['secret'])
''')
        first = worker.call(authentication=observation())
        second = worker.call(authentication=observation())
        self.assertTrue(first['auth_allowed'], first)
        self.assertFalse(second['auth_allowed'], second)
        self.assertNotIn('DO-NOT-RETAIN', str(first) + str(second))
        shutdown = worker.exchange({'_shutdown': True})
        self.assertFalse(shutdown['ok'])
        self.assertNotIn('DO-NOT-RETAIN', str(shutdown))

    def test_cannot_upgrade_aaa(self):
        for baseline in ('rejected', 'unavailable'):
            worker = self.worker('def main(api, state): api.auth.allowed = True')
            result = worker.call(authentication=observation(baseline))
            self.assertTrue(result['ok'], result)
            self.assertFalse(result['auth_allowed'], result)

    def test_failures_do_not_publish_credentials(self):
        for body in ("raise ValueError(api.auth.password)", "return api.auth.password",
                     "api.auth.allowed = 'yes'"):
            worker = self.worker('def main(api, state):\n    ' + body)
            result = worker.call(authentication=observation())
            self.assertFalse(result['ok'], result)
            self.assertFalse(result['auth_allowed'], result)
            self.assertNotIn('DO-NOT-RETAIN', str(result))
            self.assertTrue(result['_worker_recycle'])


if __name__ == '__main__':
    unittest.main()

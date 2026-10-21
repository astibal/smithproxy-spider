import multiprocessing
import pathlib
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import SharedStorage, StorageBusy


def increment_many(directory):
    shared = SharedStorage(directory).namespace('stats')
    for _ in range(20):
        for attempt in range(20):
            try:
                shared.increment('n')
                break
            except StorageBusy:
                if attempt == 19: raise
                time.sleep(.01)


class StorageTests(unittest.TestCase):
    def test_persistence_namespaces_and_atomicity(self):
        with tempfile.TemporaryDirectory() as directory:
            a = SharedStorage(directory).namespace('stats')
            self.assertEqual(a.get('missing', 7), 7)
            a.set('n', 0)
            processes = [multiprocessing.Process(target=increment_many, args=(directory,)) for _ in range(4)]
            try:
                for process in processes: process.start()
                for process in processes:
                    process.join(10)
                    self.assertEqual(process.exitcode, 0)
            finally:
                for process in processes:
                    if process.is_alive(): process.terminate()
                    if process.pid is not None: process.join()
            self.assertEqual(SharedStorage(directory).namespace('stats').get('n'), 80)
            self.assertIsNone(SharedStorage(directory).namespace('other').get('n'))
            self.assertTrue(a.delete('n'))
            self.assertFalse(a.delete('n'))
            self.assertEqual(pathlib.Path(directory, 'shared.sqlite3').stat().st_mode & 0o777, 0o600)

    def test_quota_validation_and_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            a = SharedStorage(directory).namespace('stats')
            a.set('value', {'ok': True})
            for bad in (b'bytes', float('nan'), 'x' * 65537):
                with self.assertRaises((TypeError, ValueError)): a.set('value', bad)
                self.assertEqual(a.get('value'), {'ok': True})
            with self.assertRaises(TypeError): a.increment('value')
            with self.assertRaises(ValueError): a.set('', 1)
            with self.assertRaises(TypeError): a.increment('n', True)
            with sqlite3.connect(str(pathlib.Path(directory, 'shared.sqlite3'))) as lock:
                lock.execute('BEGIN IMMEDIATE')
                with self.assertRaises(StorageBusy): a.set('n', 4)

    def test_total_quotas_roll_back(self):
        with tempfile.TemporaryDirectory() as directory:
            a = SharedStorage(directory).namespace('stats')
            a.set('seed', 0)
            filename = str(pathlib.Path(directory, 'shared.sqlite3'))
            with sqlite3.connect(filename) as db:
                db.executemany('INSERT INTO kv VALUES(?,?,?)', [('stats', str(i), '0') for i in range(4095)])
            with self.assertRaises(ValueError): a.set('overflow', 0)
            self.assertIsNone(a.get('overflow'))
            a.set('seed', 1)  # Updating an existing key remains possible at the key limit.
            with sqlite3.connect(filename) as db:
                db.execute('DELETE FROM kv')
                db.executemany('INSERT INTO kv VALUES(?,?,?)', [('stats', str(i), '"' + 'x' * 59998 + '"') for i in range(279)])
            with self.assertRaises(ValueError): a.set('overflow', 'x' * 59998)
            self.assertIsNone(a.get('overflow'))


if __name__ == '__main__': unittest.main()

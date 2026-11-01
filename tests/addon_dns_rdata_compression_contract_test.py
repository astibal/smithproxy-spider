"""Guard compressed DNS RDATA normalization from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_dns_rdata_compression_v12.json'


class DNSRDataCompressionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads(CORPUS.read_text())['records']

    def test_reference_normalizes_supported_name_bearing_records(self):
        normalized = {
            name
            for name, value in self.records.items()
            if value['output'] != value['input']
        }
        self.assertEqual(normalized, {
            'AFSDB',
            'CNAME',
            'MB',
            'MD',
            'MF',
            'MG',
            'MINFO',
            'MR',
            'MX',
            'NAPTR',
            'NS',
            'PTR',
            'PX',
            'RP',
            'RT',
            'SOA',
            'SRV',
        })

    def test_unrecognized_or_opaque_formats_remain_opaque(self):
        opaque = {
            name
            for name, value in self.records.items()
            if value['output'] == value['input']
        }
        self.assertEqual(opaque, {
            'DNAME',
            'HTTPS',
            'KX',
            'NSEC',
            'RRSIG',
            'SVCB',
            'TKEY',
            'TSIG',
        })

    def test_normalized_output_contains_no_compression_pointer(self):
        for name, value in self.records.items():
            if value['output'] == value['input']:
                continue
            with self.subTest(record=name):
                self.assertNotIn('c00c', value['output'])


if __name__ == '__main__':
    unittest.main()

"""Keep every checked reference corpus behind an executable test gate."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / 'tests'
CORPUS = TESTS / 'corpus'
CMAKE = ROOT / 'CMakeLists.txt'


class CorpusInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpora = tuple(sorted(CORPUS.glob('*.json')))
        cls.test_sources = {
            path: path.read_text()
            for path in sorted(TESTS.glob('*_test.py'))
            if path.name != Path(__file__).name
        }
        cls.cmake = CMAKE.read_text()

    def test_every_reference_corpus_is_named_by_a_direct_test(self):
        missing = []
        for corpus in self.corpora:
            if not any(
                    corpus.name in source
                    for source in self.test_sources.values()):
                missing.append(corpus.name)

        self.assertEqual(
            missing,
            [],
            'Reference corpora without an executable contract: ' +
            ', '.join(missing),
        )

    def test_every_corpus_identifies_the_audited_patch_release(self):
        accepted = {'12.3.1', 'mitmproxy 12.3.1'}
        invalid = {}
        for corpus in self.corpora:
            reference = json.loads(corpus.read_text()).get('reference')
            if reference not in accepted:
                invalid[corpus.name] = reference

        self.assertEqual(
            invalid,
            {},
            'Reference corpora with missing or stale release metadata: ' +
            repr(invalid),
        )

    def test_every_corpus_consuming_test_is_registered_with_ctest(self):
        unregistered = []
        corpus_names = tuple(path.name for path in self.corpora)
        for path, source in self.test_sources.items():
            if not any(name in source for name in corpus_names):
                continue
            relative = path.relative_to(ROOT).as_posix()
            if relative not in self.cmake:
                unregistered.append(relative)

        self.assertEqual(
            unregistered,
            [],
            'Corpus contract tests missing from CTest: ' +
            ', '.join(unregistered),
        )

    def test_reference_corpora_stay_out_of_runtime_source(self):
        runtime_mentions = []
        corpus_names = tuple(path.name for path in self.corpora)
        for path in sorted((ROOT / 'src').rglob('*.py')):
            source = path.read_text()
            if any(name in source for name in corpus_names):
                runtime_mentions.append(path.relative_to(ROOT).as_posix())

        self.assertEqual(
            runtime_mentions,
            [],
            'Reference corpus leaked into runtime source: ' +
            ', '.join(runtime_mentions),
        )


if __name__ == '__main__':
    unittest.main()

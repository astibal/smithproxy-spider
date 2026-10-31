"""Offline command contracts and generation integration; no reference imports."""

import json
from collections.abc import Sequence
from io import StringIO
import inspect
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import addon_commands as command
import addon_flow as flow
import addon_types as command_types
from addon_command_extended_types_contract import collect as collect_extended_types
from addon_command_parser_contract import collect as collect_parser
from addon_command_registration_edges_contract import collect as collect_registration_edges
from addon_command_types_contract import collect as collect_types
from addon_command_contract import collect, collect_lifecycle
from addon_command_async_contract import collect as collect_async
from addon_manager import AddonManager
from addon_options import Options
from addon_runtime import AddonGeneration


class CommandTests(unittest.IsolatedAsyncioTestCase):
    def test_reference_command_registration_edges(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_command_registration_edges_v12.json').read_text()
        )

        with self.assertLogs(level='WARNING') as diagnostics:
            actual = collect_registration_edges(command)

        self.assertEqual(actual, corpus['observations'])
        self.assertEqual(len(diagnostics.output), 1)
        self.assertIn('edge.owner', diagnostics.output[0])

    async def test_reference_asynchronous_command_contract(self):
        master = SimpleNamespace()
        master.commands = command.CommandManager(master)
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_command_async_v12.json').read_text()
        )

        self.assertEqual(
            await collect_async(command, lambda: master),
            corpus['observations'],
        )

    def test_reference_incremental_command_parser(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_command_parser_v12.json').read_text())
        self.assertEqual(collect_parser(command, command_types), corpus['cases'])

    def test_incremental_parser_keeps_quoted_arguments_for_type_validation(self):
        manager = command.CommandManager(SimpleNamespace())

        def add(first: int, second: int = 2) -> int:
            return first + second

        manager.add('add', add)
        parsed, remaining = manager.parse_partial('  add "1"')

        self.assertEqual(
            parsed,
            [
                command.ParseResult('  ', command_types.Space, True),
                command.ParseResult('add', command_types.Cmd, True),
                command.ParseResult(' ', command_types.Space, True),
                command.ParseResult('"1"', int, False),
            ],
        )
        self.assertEqual(
            remaining,
            [command.CommandParameter('second', int)],
        )

    def test_public_command_metadata_preparation_and_dump(self):
        manager = command.CommandManager(SimpleNamespace())

        def choices() -> Sequence[str]:
            """Return choices."""
            return ['one', 'two']

        def sample(text: str, count: int = 2, *rest: bool) -> str:
            """First line of help.

            More details.
            """
            return text * count

        def defaults(flag: bool = True, text: str = r'line\n') -> str:
            return str((flag, text))

        manager.add('z.last', choices)
        manager.add('probe.sample', sample)
        manager.add('a.first', choices)
        registered = manager.commands['probe.sample']

        self.assertIsInstance(registered, command.Command)
        self.assertEqual(registered.name, 'probe.sample')
        self.assertIs(registered.func, sample)
        self.assertEqual(registered.help, 'First line of help.  More details.')
        self.assertIs(registered.return_type, str)
        self.assertEqual(
            registered.parameters,
            [
                command.CommandParameter('text', str),
                command.CommandParameter('count', int),
                command.CommandParameter(
                    'rest', bool, inspect.Parameter.VAR_POSITIONAL),
            ],
        )
        self.assertEqual(
            registered.signature_help(),
            'probe.sample text count *rest -> str',
        )

        prepared = registered.prepare_args(('x', '3', 'true', 'false'))
        self.assertEqual(
            list(prepared.arguments.items()),
            [('text', 'x'), ('count', 3), ('rest', (True, False))],
        )
        self.assertEqual(registered.call(('x', '3')), 'xxx')
        self.assertEqual(registered.call(('x', 3)), 'xxx')
        with self.assertRaisesRegex(command.CommandError, r'Received: \(\)'):
            registered.prepare_args(())

        manager.add('probe.defaults', defaults)
        prepared_defaults = manager.commands['probe.defaults'].prepare_args(())
        self.assertEqual(
            list(prepared_defaults.arguments.items()),
            [('flag', True), ('text', r'line\n')],
        )
        prepared_override = manager.commands['probe.defaults'].prepare_args(
            ('false', r'next\n'))
        self.assertEqual(
            list(prepared_override.arguments.items()),
            [('flag', False), ('text', 'next\n')],
        )

        output = StringIO()
        self.assertIsNone(manager.dump(output))
        self.assertEqual(
            output.getvalue(),
            '# Return choices.\n'
            'a.first  -> str[]\n\n'
            'probe.defaults flag text -> str\n\n'
            '# First line of help.  More details.\n'
            'probe.sample text count *rest -> str\n\n'
            '# Return choices.\n'
            'z.last  -> str[]\n\n',
        )

    def test_reference_completion_contract_for_cut_data_and_paths(self):
        manager = command.CommandManager(SimpleNamespace())

        cut = command_types.CommandTypes.get(command_types.CutSpec)
        fields = cut.completion(manager, command_types.CutSpec, 'ignored')
        self.assertEqual(len(fields), 32)
        self.assertEqual(fields[:4], [
            'request.method', 'request.scheme', 'request.host',
            'request.http_version',
        ])
        self.assertEqual(fields[-3:], [
            'server_conn.tls_version', 'server_conn.sni',
            'server_conn.tls_established',
        ])

        data = command_types.CommandTypes.get(command_types.Data)
        with self.assertRaisesRegex(ValueError, 'data cannot be passed as argument'):
            data.completion(manager, command_types.Data, '')

        path_type = command_types.CommandTypes.get(command_types.Path)
        previous = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'alpha.txt').write_text('alpha')
                (root / '.hidden').write_text('hidden')
                (root / 'folder').mkdir()
                (root / 'folder' / 'item.txt').write_text('item')
                os.chdir(root)

                self.assertEqual(
                    path_type.completion(manager, command_types.Path, ''),
                    ['./alpha.txt', './folder/'],
                )
                self.assertEqual(
                    path_type.completion(manager, command_types.Path, 'fold'),
                    ['folder/'],
                )
                self.assertEqual(
                    path_type.completion(manager, command_types.Path, 'folder'),
                    ['folder/item.txt'],
                )
                self.assertEqual(
                    path_type.completion(manager, command_types.Path, 'missing'),
                    ['missing'],
                )
        finally:
            os.chdir(previous)

    def test_marker_and_home_path_completions_do_not_leak_internal_state(self):
        manager = command.CommandManager(SimpleNamespace())

        marker_type = command_types.CommandTypes.get(command_types.Marker)
        first_markers = marker_type.completion(
            manager, command_types.Marker, 'ignored')
        second_markers = marker_type.completion(
            manager, command_types.Marker, 'ignored')

        self.assertEqual(first_markers, second_markers)
        self.assertIsNot(first_markers, second_markers)
        first_markers.append(':test-only:')
        self.assertNotIn(':test-only:', second_markers)

        def expand_home(value):
            if value == '~':
                return '/fake/home'
            if value == '~/pro':
                return '/fake/home/pro'
            return value

        path_type = command_types.CommandTypes.get(command_types.Path)
        with patch.object(
                command_types.os.path,
                'expanduser',
                side_effect=expand_home,
        ), patch.object(
                command_types.glob,
                'glob',
                return_value=['/fake/home/project'],
        ), patch.object(
                command_types.os.path,
                'isdir',
                return_value=False,
        ):
            completed = path_type.completion(
                manager, command_types.Path, '~/pro')

        self.assertEqual(completed, ['~/project'])

    def test_reference_extended_command_types(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_command_extended_types_v12.json').read_text())
        self.assertEqual(collect_extended_types(command, command_types), corpus['cases'])

    def test_reference_command_types(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_command_types_v12.json').read_text())
        http = SimpleNamespace(HTTPFlow=flow.HTTPFlow)
        self.assertEqual(collect_types(command, flow, http), corpus['cases'])

    def test_reference_call_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_commands_v12.json').read_text())
        with self.assertLogs(level='WARNING') as diagnostics:
            actual = collect(command)
        self.assertEqual(actual, corpus['cases'])
        self.assertEqual(len(diagnostics.output), 1)
        self.assertIn('probe.invalid', diagnostics.output[0])

    async def test_reference_registration_lifecycle(self):
        def factory():
            options = Options()
            master = SimpleNamespace()
            master.commands = command.CommandManager(master)
            master.addons = AddonManager(options, {'load', 'done'})
            master.addons.commands = master.commands
            return master

        corpus = json.loads((ROOT / 'tests/corpus/addon_commands_v12.json').read_text())
        self.assertEqual(await collect_lifecycle(command, factory), corpus['lifecycle'])

    async def test_commands_share_generation_state_without_cross_generation_leaks(self):
        source = '''from mitmproxy import command, ctx
count = 0
@command.command("probe.increment")
def increment(amount: int) -> int:
    global count
    count += amount
    return count
def running():
    assert ctx.master.commands.call("probe.increment", 2) == 2
def request(flow):
    flow.metadata["count"] = ctx.master.commands.execute("probe.increment 3")
'''
        generations = [AddonGeneration(source, {'request'}) for _ in range(2)]
        try:
            for generation in generations:
                self.assertEqual(await generation.start(), ())
            for generation, expected in ((generations[0], 5), (generations[0], 8),
                                         (generations[1], 5)):
                flow = SimpleNamespace(metadata={})
                self.assertEqual(await generation.dispatch('request', flow), ())
                self.assertEqual(flow.metadata['count'], expected)
        finally:
            for generation in generations:
                await generation.close()

    def test_direct_decorator_preserves_callback_errors(self):
        @command.command()
        def broken(value: str) -> str:
            raise TypeError('inside callback')

        self.assertEqual(broken.command_name, 'broken')
        with self.assertRaises(command.CommandError):
            broken()
        with self.assertRaisesRegex(TypeError, 'inside callback'):
            broken('value')


if __name__ == '__main__':
    unittest.main()

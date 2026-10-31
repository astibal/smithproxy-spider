"""Original public command API observations, shared with the reference probe."""

from types import SimpleNamespace
import re


def collect(command):
    cases = {}

    def record(name, operation):
        try:
            cases[name] = {'value': operation()}
        except Exception as error:
            message = re.sub(r'0x[0-9a-fA-F]+', '0xADDRESS', str(error))
            cases[name] = {'error': type(error).__name__, 'message': message}

    class Commands:
        @command.command('probe.echo')
        def echo(self, text: str) -> str:
            return text

        @command.command('probe.add')
        def add(self, first: int, second: int = 2) -> int:
            return first + second

        @command.command('probe.flag')
        def flag(self, value: bool) -> bool:
            return value

        @command.command('probe.fail')
        def fail(self) -> None:
            raise ValueError('callback failed')

    master = SimpleNamespace()
    manager = command.CommandManager(master)
    master.commands = manager
    record('collect', lambda: manager.collect_commands(Commands()))
    for name, path, arguments in (
        ('string', 'probe.echo', ('hello',)),
        ('string_type', 'probe.echo', (42,)),
        ('add', 'probe.add', (3, 4)),
        ('default', 'probe.add', (3,)),
        ('missing', 'probe.add', ()),
        ('extra', 'probe.echo', ('a', 'b')),
        ('unknown', 'probe.unknown', ()),
        ('failure', 'probe.fail', ()),
    ):
        record('call/' + name, lambda path=path, arguments=arguments:
               manager.call(path, *arguments))
    for name, path, arguments in (
        ('add', 'probe.add', ('3', '4')),
        ('default', 'probe.add', ('3',)),
        ('bad_int', 'probe.add', ('three', '4')),
        ('flag_true', 'probe.flag', ('true',)),
        ('flag_false', 'probe.flag', ('false',)),
        ('flag_upper', 'probe.flag', ('True',)),
        ('flag_one', 'probe.flag', ('1',)),
        ('echo_quoted', 'probe.echo', ('"two words"',)),
        ('echo_escape', 'probe.echo', (r'line\nnext',)),
        ('echo_quoted_escape', 'probe.echo', (r'"line\nnext"',)),
        ('echo_unicode', 'probe.echo', ('čaj',)),
        ('echo_bad_hex', 'probe.echo', (r'\xZZ',)),
        ('echo_trailing_slash', 'probe.echo', ('tail\\',)),
    ):
        record('strings/' + name, lambda path=path, arguments=arguments:
               manager.call_strings(path, arguments))
    for expression in ('probe.echo hello', 'probe.echo "two words"',
                       'probe.add 3 4', 'probe.echo', 'probe.missing', '',
                       'probe.echo ""', "probe.echo ''", '  probe.echo hello  ',
                       'probe.echo "unfinished', "probe.echo 'unfinished",
                       'probe.echo one\\ two', r'probe.echo "line\nnext"',
                       r"probe.echo 'line\nnext'", r'probe.echo "a\"b"',
                       'probe.echo a"b"', 'probe.echo "a"b',
                       'probe.echo #text', 'probe.echo "\\x41"',
                       'probe.echo "\\u0041"', 'probe.echo "\\q"',
                       'probe.echo $HOME', 'probe.echo a;b', 'probe.echo a|b',
                       'probe.echo a\tb', 'probe.echo "two\nlines"',
                       'probe.echo "unfinished words', r'probe.echo line\nnext',
                       'probe.echo čaj', 'probe.echo "čaj"', r'probe.echo "\xZZ"'):
        record('execute/' + expression, lambda expression=expression: manager.execute(expression))

    def wrong_result() -> int:
        return 'not an integer'

    def replacement() -> str:
        return 'replacement'

    def float_value(value: float) -> float:
        return value

    record('register/wrong_result', lambda: manager.add('probe.result', wrong_result))
    record('result/typed', lambda: manager.call('probe.result'))
    record('result/strings', lambda: manager.call_strings('probe.result', []))
    record('register/replacement', lambda: manager.add('probe.result', replacement))
    record('result/replaced', lambda: manager.call('probe.result'))
    record('register/float', lambda: manager.add('probe.float', float_value))
    record('float/strings', lambda: manager.call_strings('probe.float', ['1.5']))

    def bad_return() -> float:
        return 1.5

    def untyped(value):
        return value

    record('register/bad_return', lambda: manager.add('probe.bad_return', bad_return))
    record('register/untyped', lambda: manager.add('probe.untyped', untyped))

    class Mixed:
        @command.command('probe.invalid')
        def invalid(self, value: float) -> str:
            return str(value)

        @command.command('probe.valid')
        def valid(self) -> str:
            return 'still available'

    record('collect/mixed', lambda: manager.collect_commands(Mixed()))
    record('collect/invalid_lookup', lambda: manager.call('probe.invalid', 1.5))
    record('collect/valid_lookup', lambda: manager.call('probe.valid'))
    record('register/failed_replace', lambda: manager.add('probe.result', bad_return))
    record('register/retained_after_failure', lambda: manager.call('probe.result'))
    for prefix in ('', 'é', 'č', '😀'):
        for token in (r'\n', '\\', r'\\', r'\q', r'\xFF', r'\u0041', r'\\u0041'):
            value = prefix + token + 'č'
            record('text/' + repr(value), lambda value=value:
                   manager.call_strings('probe.echo', [value]))
    return cases


async def collect_lifecycle(command, factory):
    """Observe ownership through public addon registration and removal."""
    master = factory()
    events = []

    def invoke(label):
        try:
            events.append([label, master.commands.call('probe.owned')])
        except Exception as error:
            events.append([label, type(error).__name__])

    class Owner:
        @command.command('probe.owned')
        def owned(self) -> str:
            return 'owner'

        def load(self, loader):
            invoke('during_load')
            loader.add_command('probe.owned', self.explicit)
            invoke('after_explicit_registration')

        def explicit(self) -> str:
            return 'explicit'

        def done(self):
            invoke('during_done')

    owner = Owner()
    master.addons.add(owner)
    invoke('after_add')
    master.addons.remove(owner)
    invoke('after_remove')
    master.addons.add(owner)
    master.addons.clear()
    invoke('after_clear')
    return events

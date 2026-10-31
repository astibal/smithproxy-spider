"""Package trusted build-time source below Linux's per-argument exec limit."""
import base64
import argparse
import bz2
import json
from pathlib import Path
import sys


MAX_ARGUMENT_BYTES = 120 * 1024
MAX_PACKED_ARGUMENT_BYTES = 1024 * 1024
CHUNK_BYTES = 60 * 1024


def module_bootstrap(modules):
    """Make build-supplied modules available without loading them eagerly.

    These are Spider modules, not the temporary mitmproxy import facade exposed
    to an addon. Standard import machinery registers a module before execution,
    including for dataclasses. Native scripts pay no addon import cost.
    """
    for name, module_source in modules.items():
        if not name.isidentifier():
            raise ValueError('Bundled module names must be simple identifiers')
        compile(module_source, '<spider:' + name + '>', 'exec')
    return (
        'import sys as _bundle_sys\n'
        'from importlib.util import spec_from_loader as _bundle_spec\n'
        'class _SpiderBundledModules:\n'
        f'    sources = {modules!r}\n'
        '    def find_spec(self, fullname, path=None, target=None):\n'
        '        if fullname in self.sources:\n'
        '            return _bundle_spec(fullname, self)\n'
        '        return None\n'
        '    def create_module(self, spec):\n'
        '        return None\n'
        '    def exec_module(self, module):\n'
        '        filename = "<spider:" + module.__name__ + ">"\n'
        '        module.__file__ = filename\n'
        '        code = compile(self.sources[module.__name__], filename, "exec")\n'
        '        exec(code, module.__dict__)\n'
        '_bundle_sys.meta_path.insert(0, _SpiderBundledModules())\n'
    )


def packaged_source(source, modules=None):
    if modules:
        # Execute separately so a future import remains legal in worker source.
        bootstrap = module_bootstrap(modules)
        source = (bootstrap + '\nexec(compile(' + repr(source) +
                  ', "<spider-worker-main>", "exec"), globals())\n')
    return source


def encoded_source(source, modules=None):
    source = packaged_source(source, modules)
    # The bundled facade shares Linux's per-argument limit with the native
    # worker. Bzip2 is materially smaller than XZ for this collection of many
    # related Python modules.
    # Base85 keeps the printable launcher materially smaller than Base64 while
    # retaining one deterministic, shell-independent Python argument.
    return base64.b85encode(
        bz2.compress(source.encode('utf-8'), compresslevel=9)
    ).decode('ascii')


def pack(source, modules=None):
    """Return the compact single-argument launcher used by unit tests."""

    encoded = encoded_source(source, modules)
    launcher = ("import base64,bz2;exec(compile(bz2.decompress(base64.b85decode("
                + repr(encoded) + ")), '<spider-worker>', 'exec'), globals())")
    if len(launcher.encode()) >= MAX_ARGUMENT_BYTES:
        raise ValueError('Packed worker exceeds safe exec argument budget')
    return launcher


def pack_arguments(source, modules=None):
    """Return a small loader followed by bounded encoded data arguments.

    Linux limits each exec argument independently. Production passes the worker
    in several arguments and the loader removes them from ``sys.argv`` before
    executing it, so the worker sees exactly the command-line flags supplied
    after the payload.
    """

    encoded = encoded_source(source, modules)
    chunks = [encoded[offset:offset + CHUNK_BYTES]
              for offset in range(0, len(encoded), CHUNK_BYTES)]
    if not chunks:
        chunks = ['']

    loader = (
        "import base64,bz2,sys;"
        "_n=int(sys.argv[1]);"
        "_d=''.join(sys.argv[2:2+_n]);"
        "del sys.argv[1:2+_n];"
        "exec(compile(bz2.decompress(base64.b85decode(_d)),"
        "'<spider-worker>','exec'),globals())"
    )
    arguments = [loader, str(len(chunks)), *chunks]
    if any(len(value.encode()) >= MAX_ARGUMENT_BYTES for value in arguments):
        raise ValueError('Packed worker contains an oversized exec argument')
    if sum(len(value.encode()) + 1 for value in arguments) >= MAX_PACKED_ARGUMENT_BYTES:
        raise ValueError('Packed worker exceeds safe total exec argument budget')
    return arguments


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', action='append', default=[], metavar='PATH')
    parser.add_argument('--arguments-json', action='store_true',
                        help='Emit the production chunked argv payload as JSON')
    parser.add_argument('sources', nargs='+')
    arguments = parser.parse_args()
    modules = {}
    for value in arguments.module:
        path = Path(value)
        if path.stem in modules:
            parser.error('Duplicate bundled module: ' + path.stem)
        modules[path.stem] = path.read_text(encoding='utf-8')
    source = '\n'.join(Path(path).read_text(encoding='utf-8')
                       for path in arguments.sources)
    if arguments.arguments_json:
        print(json.dumps(pack_arguments(source, modules), separators=(',', ':')))
    else:
        print(pack(source, modules))

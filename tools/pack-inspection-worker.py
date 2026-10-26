"""Package trusted build-time source below Linux's per-argument exec limit."""
import base64
from pathlib import Path
import sys
import zlib


def pack(source):
    encoded = base64.b64encode(zlib.compress(source.encode('utf-8'), 9)).decode('ascii')
    launcher = ("import base64,zlib;exec(compile(zlib.decompress(base64.b64decode("
                + repr(encoded) + ")), '<spider-worker>', 'exec'), globals())")
    if len(launcher.encode()) >= 120 * 1024:
        raise ValueError('Packed worker exceeds safe exec argument budget')
    return launcher


if __name__ == '__main__':
    print(pack('\n'.join(Path(path).read_text() for path in sys.argv[1:])))

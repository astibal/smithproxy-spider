"""Public HTTP content-coding observations, independent of codec internals."""


def collect(response_type):
    results = {}
    for coding in ('br', 'zstd'):
        for index, body in enumerate((b'', b'hello world', bytes(range(256)), b'repeat ' * 1000)):
            response = response_type.make(200, body)
            response.encode(coding)
            wire = response.raw_content
            results[f'{coding}/encode/{index}'] = {
                'wire': wire.hex(), 'decoded': response.content.hex(),
                'length': response.headers.get('content-length'),
                'coding': response.headers.get('content-encoding'),
            }
            for variant, data in (('valid', wire), ('truncated', wire[:-1]),
                                  ('trailing', wire + b'junk'), ('double', wire + wire),
                                  ('invalid', b'invalid'), ('empty', b'')):
                message = response_type.make(200, data, {'content-encoding': coding})
                # make() encodes a decoded body. Assign raw bytes explicitly
                # to exercise incoming compressed bodies, including corruption.
                message.raw_content = data
                error = None
                decoded = None
                try:
                    decoded = message.content.hex()
                except Exception as failure:
                    error = type(failure).__name__
                results[f'{coding}/{index}/{variant}'] = {
                    'error': error, 'decoded': decoded,
                    'lenient': message.get_content(strict=False).hex(),
                    'raw_unchanged': message.raw_content == data,
                }
    return results

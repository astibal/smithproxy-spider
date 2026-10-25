"""Isolated HPACK translate experiment. NOT loaded into the production worker.

Requires python-hpack only for this harness. Input/output tables are independent
per connection direction. Each callback is a transaction; a script must return
message.translate() exactly once. Failure poisons the experiment connection.
"""
import copy
import pathlib
import sys
from types import SimpleNamespace

import hpack

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import (
    Message, CommitException, H2Headers, HpackField, _h2_length_overrides, _h2_content_groups,
    _hpack_fields,
)


class TranslateError(CommitException):
    pass


class TranslateMessage(Message):
    def commit(self, *args, **kwargs):
        raise TranslateError('Translate callback must call message.translate()')

    def translate(self):
        if self._translated is not None:
            raise TranslateError('Translate must be called exactly once')
        if self.parts._held_from is not None:
            raise TranslateError('POC accepts complete blocks only; hold is not integrated')
        if tuple(id(part) for part in self.parts) != self._part_ids:
            raise TranslateError('POC does not support inserting/removing/reordering parts')

        # Derived lengths are calculated on drafts, not by mutating source bytes.
        overrides = _h2_length_overrides(self)
        output = bytearray()
        encoder = copy.deepcopy(self._encoder)

        for part, original in zip(self.parts, self._originals):
            if part.frame_type not in (1, 5):
                if part.commit() != original:
                    raise TranslateError('POC translates headers only; DATA/control edits are unsupported')
                output.extend(original)
                if len(output) > 1024 * 1024:
                    raise TranslateError('Translated output exceeds 1 MiB')
                continue

            if part._pending is not None or part.headers is None:
                raise TranslateError('Translate requires logical headers, not raw HPACK replacement')

            fields = part.headers.entries
            if id(part) in overrides:
                fields = _hpack_fields(overrides[id(part)], None)

            headers = []
            for field in fields:
                if (not isinstance(field.name, bytes) or not isinstance(field.value, bytes)
                        or field.index or field.name_index
                        or field.indexing not in ('without', 'incremental', 'never')):
                    raise TranslateError('Translate requires resolved byte fields; explicit HPACK indices are rewrite-only')
                headers.append((field.name, field.value, field.indexing == 'never'))

            # The output encoder alone owns peer-facing compression state.
            encoded = encoder.encode(headers, huffman=True)
            output.extend(part._assemble(encoded))

            if len(output) > 1024 * 1024:
                raise TranslateError('Translated output exceeds 1 MiB')

        result = bytes(output)
        object.__setattr__(self, '_translated', result)
        object.__setattr__(self, '_next_encoder', encoder)
        return result


class TranslateConnection:
    """One fresh connection; start before its first HPACK block, never mid-capture."""
    def __init__(self, instancing='flow'):
        if instancing != 'flow':
            raise TranslateError('Translate requires flow instancing')
        self._directions = {
            side: (hpack.Decoder(), hpack.Encoder()) for side in ('L', 'R')
        }
        self.failed = False

    def run(self, side, payload, annotations, script):
        if self.failed:
            raise TranslateError('Connection failed; cannot resume translation')

        try:
            if side not in self._directions:
                raise TranslateError('Direction must be L or R')
            decoder, encoder = self._directions[side]
            decoder = copy.deepcopy(decoder)
            message = TranslateMessage(payload, len(payload), {'content_annotations': annotations})

            for part in message.parts:
                if not part.complete or part.frame_type is None or part.frame_type in (4, 9):
                    raise TranslateError('POC requires complete annotated frames; SETTINGS and orphan CONTINUATION are unsupported')
                if part.frame_type in (1, 5):
                    # Always consume the original block, even if the script will
                    # replace its fields. Never decode rewritten bytes as input.
                    fields = decoder.decode(part.get_bytes(), raw=True)
                    part.headers = H2Headers([
                        HpackField(name, value, 'never' if not field.indexable else 'without', 0, 0)
                        for field in fields for name, value in [field]
                    ])

            object.__setattr__(message, '_part_ids', tuple(id(p) for p in message.parts))
            object.__setattr__(message, '_body_sizes', {
                id(group[0]): sum(len(p._data) for p in group if p.frame_type == 0)
                for group in _h2_content_groups(message.parts)
            })
            object.__setattr__(message, '_originals', tuple(bytes(p._wire) for p in message.parts))
            object.__setattr__(message, '_encoder', encoder)
            object.__setattr__(message, '_translated', None)
            result = script(SimpleNamespace(message=message, print=print))

            if message._translated is None or result is not message._translated:
                raise TranslateError('Script must return its explicit message.translate() result')

            # Publish both table states only after successful script completion.
            self._directions[side] = (decoder, message._next_encoder)
            return result
        except BaseException:
            self.failed = True
            raise

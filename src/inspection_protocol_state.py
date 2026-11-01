"""Spider-local protocol state, independent of addon hooks and socket state.

Its owner supplies native Parts after hold restoration and before script edits. Publication
and suspension are separate transitions; parsing a message never sends it.
"""

from __future__ import annotations

from dataclasses import MISSING, asdict, dataclass, field, replace


def _observation(description, example, default=MISSING):
    """Schema metadata without importing the API module that consumes us."""
    safety = 'Read-only observation; does not select or change commit safety.'
    return field(default=default, metadata={
        'description': description,
        'example': example,
        'availability': 'Flow callbacks after track_protocols() during setup.',
        'access': 'read-only snapshot',
        'easy': safety,
        'expert': safety,
    })


def _state_object(value, names):
    """Check data-only storage shape before constructing immutable records."""
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('Invalid protocol state fields')

    return value


def _state_bool(value, *, optional=False):
    if type(value) is bool or (optional and value is None):
        return value

    raise ValueError('Expected a boolean protocol state flag')


def _state_number(value, maximum=2**63 - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('Invalid protocol state counter')

    return value


def _message_flags(value):
    """Storage validation must preserve unknown completeness, not coerce it."""
    headers = _state_bool(value['headers_complete'])
    complete = _state_bool(value['content_complete'], optional=True)
    suspended = _state_bool(value['suspended'])
    published = _state_bool(value['published'], optional=True)

    # Reception and processing are independent, but publication requires both
    # a complete message and a released suspension.
    if suspended and (not headers or published):
        raise ValueError('Invalid suspended message state')

    if published and (not headers or complete is not True):
        raise ValueError('Invalid published message state')

    return headers, complete, suspended, published


@dataclass(frozen=True)
class H1MessageState:
    """One local directional message, identified by order rather than stream ID.

    The sequence does not pair requests with responses: informational responses
    are messages too. Neither direction's sequence is a transport identifier.
    """

    sequence: int = _observation('Directional message sequence, not an exchange ID.',
        'for message in api.http1.state or ():\n    api.print(message.sequence)')
    side: str = _observation('L for client input; R for server input.',
        'for message in api.http1.state or ():\n    api.print(message.side)')
    headers_complete: bool = _observation('Native Parts supplied complete headers.',
        'for message in api.http1.state or ():\n    api.print(message.headers_complete)')
    content_complete: bool | None = _observation('Complete received content; None means unknown.',
        'for message in api.http1.state or ():\n    api.print(message.content_complete)')
    informational: bool = _observation('An informational response, separate from the final response.',
        'for message in api.http1.state or ():\n    api.print(message.informational)', False)
    suspended: bool = _observation('Spider retains this message locally, independently of input completeness.',
        'for message in api.http1.state or ():\n    api.print(message.suspended)', False)
    published: bool | None = _observation('Complete local publication, not peer delivery. None after an untracked raw replacement.',
        'for message in api.http1.state or ():\n    api.print(message.published)', False)


class H1StateTable:
    """Local HTTP/1 message order supplied by native Header/Body Parts."""

    def __init__(self, max_messages=1024):
        if type(max_messages) is not int or max_messages < 1:
            raise ValueError('Expected a positive message limit')

        self._limit = max_messages
        self._messages = {}
        self._sequences = {'L': 0, 'R': 0}

    def fork(self):
        candidate = H1StateTable(self._limit)
        candidate._messages = dict(self._messages)
        candidate._sequences = dict(self._sequences)
        return candidate

    def snapshot(self):
        return tuple(self._messages[key] for key in sorted(self._messages))

    def checkpoint(self):
        """Return detached JSON data; never retain a script-owned dictionary."""
        return {
            'version': 1,
            'sequences': dict(self._sequences),
            'messages': [asdict(message) for message in self.snapshot()],
        }

    @classmethod
    def from_checkpoint(cls, value, *, max_messages=1024):
        # Reject an incompatible envelope before reconstructing any records.
        _state_object(value, ('version', 'sequences', 'messages'))
        if type(value['version']) is not int or value['version'] != 1:
            raise ValueError('Unsupported HTTP/1 state checkpoint')

        sequences = _state_object(value['sequences'], ('L', 'R'))
        messages = value['messages']
        table = cls(max_messages)

        if type(messages) is not list or len(messages) > max_messages:
            raise ValueError('Invalid HTTP/1 state message list')

        # Counters outlive retired messages. Restoring them first lets us check
        # that each retained message belongs to the recorded history.
        for side in ('L', 'R'):
            table._sequences[side] = _state_number(sequences[side])

        for item in messages:
            _state_object(item, (
                'sequence', 'side', 'headers_complete', 'content_complete',
                'informational', 'suspended', 'published',
            ))
            _message_flags(item)
            _state_bool(item['informational'])

            side = item['side']
            sequence = _state_number(item['sequence'])

            if type(side) is not str or side not in ('L', 'R'):
                raise ValueError('Invalid HTTP/1 state direction')

            if not 0 < sequence <= table._sequences[side]:
                raise ValueError('Invalid HTTP/1 state sequence')

            key = (side, sequence)
            if key in table._messages:
                raise ValueError('Duplicate HTTP/1 state message')

            if item['headers_complete'] is not True:
                raise ValueError('HTTP/1 state message has no observed head')

            table._messages[key] = H1MessageState(**item)

        return table

    def retire(self, side, sequence):
        self._messages.pop((side, sequence), None)

    def observe(self, side, parts, *, restored=False):
        if side not in ('L', 'R'):
            raise ValueError('Expected side L or R')

        # Work on a candidate so a rejected later Part cannot leave half of
        # this callback's observations in the original table.
        candidate = self.fork()
        identities = []

        for part in parts:
            if part.type == 'http1.header':
                if not part.complete or part.http1 is None:
                    continue

                # Restored headers keep their message identity. Their body may
                # have grown, but that is not a second request or response.
                sequence = None
                if restored:
                    sequence = getattr(part, '_inspection_h1_sequence', None)

                if sequence is not None:
                    if getattr(part, '_inspection_side', None) != side:
                        raise ValueError('Restored HTTP/1 message direction changed')

                    if (side, sequence) not in candidate._messages:
                        raise ValueError('Restored HTTP/1 message state is missing')

                    identities.append((part, sequence))
                    continue

                if len(candidate._messages) >= self._limit:
                    raise ValueError('Protocol state message limit exceeded')

                # Each complete head starts a directional message, including
                # informational responses. It does not pair an exchange.
                candidate._sequences[side] += 1
                sequence = candidate._sequences[side]
                _state_number(sequence)

                status = part.http1.status_code
                informational = status is not None and 100 <= status < 200
                candidate._messages[(side, sequence)] = H1MessageState(
                    sequence, side, True, part.content.complete, informational,
                )
                identities.append((part, sequence))

            elif part.type == 'http1.body':
                sequence = None
                if restored:
                    sequence = getattr(part, '_inspection_h1_sequence', None)

                if sequence is not None and getattr(part, '_inspection_side', None) != side:
                    raise ValueError('Restored HTTP/1 body direction changed')

                if sequence is not None and (side, sequence) not in candidate._messages:
                    raise ValueError('Restored HTTP/1 body state is missing')

                if sequence is None:
                    # A Body belongs to the preceding head in this Parts list,
                    # including when the head was restored from an older hold.
                    sequence = candidate._sequences[side]
                    if identities:
                        sequence = identities[-1][1]

                key = (side, sequence)
                message = candidate._messages.get(key)

                # A mid-message observation is not proof that we saw its head.
                # Keep it unavailable rather than inventing a new exchange.
                if message is None:
                    continue

                complete = part.content.complete
                if message.content_complete is True:
                    complete = True

                candidate._messages[key] = replace(message, content_complete=complete)
                identities.append((part, sequence))

        # Adopt only the fully validated batch.
        for part, sequence in identities:
            part._inspection_h1_sequence = sequence
            part._inspection_side = side

        self._messages = candidate._messages
        self._sequences = candidate._sequences

    def suspend(self, side, sequence):
        self._processing(side, sequence, suspended=True)

    def resume(self, side, sequence):
        self._processing(side, sequence, suspended=False)

    def publish(self, side, sequence):
        self._processing(side, sequence, published=True)

    def _processing(self, side, sequence, *, suspended=None, published=False):
        key = (side, sequence)
        message = self._messages.get(key)
        if message is None:
            raise ValueError('Expected an observed HTTP/1 message')

        if published:
            if message.suspended or message.content_complete is not True:
                raise ValueError('Cannot publish a suspended or incomplete message')

            message = replace(message, published=True)
        else:
            if message.published:
                raise ValueError('Cannot change suspension after publication')

            message = replace(message, suspended=suspended)

        self._messages[key] = message


@dataclass(frozen=True)
class H2MessageState:
    """Local progress of one direction; None means content is not yet known."""

    headers_complete: bool = _observation('Complete initial headers were observed in this direction.',
        'for stream in api.http2.state or ():\n    api.print(stream.request.headers_complete)', False)
    content_complete: bool | None = _observation('END_STREAM was observed; None before message input is known.',
        'for stream in api.http2.state or ():\n    api.print(stream.request.content_complete)', None)
    suspended: bool = _observation('Spider retains this direction locally.',
        'for stream in api.http2.state or ():\n    api.print(stream.request.suspended)', False)
    published: bool | None = _observation('Complete local publication, not peer delivery. None for untracked output.',
        'for stream in api.http2.state or ():\n    api.print(stream.request.published)', False)


@dataclass(frozen=True)
class H2StreamState:
    """Request and response progress, not an RFC stream-state enumeration."""

    stream_id: int = _observation('Native HTTP/2 stream identifier within this connection.',
        'for stream in api.http2.state or ():\n    api.print(stream.stream_id)')
    request: H2MessageState = _observation('Client-side reception and local processing.',
        'for stream in api.http2.state or ():\n    api.print(stream.request)', H2MessageState())
    response: H2MessageState = _observation('Server-side reception and local processing.',
        'for stream in api.http2.state or ():\n    api.print(stream.response)', H2MessageState())
    reset: bool = _observation('A native stream reset was observed; not inferred from GOAWAY.',
        'for stream in api.http2.state or ():\n    api.print(stream.reset)', False)


class H2StateTable:
    """Bounded local state for one connection, with private candidate updates.

    Immutable records make fork cheap and keep old script snapshots stable.
    The owner adopts a candidate only after successful callback publication.
    No Parts, payloads, HPACK tables or addon objects are retained here.
    """

    def __init__(self, max_streams=1024):
        if type(max_streams) is not int or max_streams < 1:
            raise ValueError('Expected a positive stream limit')

        self._limit = max_streams
        self._streams = {}

    def fork(self):
        candidate = H2StateTable(self._limit)
        candidate._streams = dict(self._streams)
        return candidate

    def snapshot(self):
        return tuple(self._streams[key] for key in sorted(self._streams))

    def checkpoint(self):
        return {
            'version': 1,
            'streams': [asdict(stream) for stream in self.snapshot()],
        }

    @classmethod
    def from_checkpoint(cls, value, *, max_streams=1024):
        # Validate the envelope and bound the allocation before restoring
        # stream records and their two independent message directions.
        _state_object(value, ('version', 'streams'))
        if type(value['version']) is not int or value['version'] != 1:
            raise ValueError('Unsupported HTTP/2 state checkpoint')

        streams = value['streams']
        table = cls(max_streams)

        if type(streams) is not list or len(streams) > max_streams:
            raise ValueError('Invalid HTTP/2 state stream list')

        for item in streams:
            _state_object(item, ('stream_id', 'request', 'response', 'reset'))
            stream_id = _state_number(item['stream_id'], 2**31 - 1)

            if stream_id == 0 or stream_id in table._streams:
                raise ValueError('Invalid or duplicate HTTP/2 state stream')

            reset = _state_bool(item['reset'])
            directions = {}

            # A reset belongs to the stream, so neither message may retain
            # a suspension even when only one direction had received data.
            for name in ('request', 'response'):
                message = _state_object(item[name], (
                    'headers_complete', 'content_complete', 'suspended', 'published',
                ))
                _message_flags(message)

                if reset and message['suspended']:
                    raise ValueError('Reset stream cannot remain suspended')

                directions[name] = H2MessageState(**message)

            table._streams[stream_id] = H2StreamState(stream_id, reset=reset, **directions)

        return table

    def stream(self, stream_id):
        return self._streams.get(stream_id)

    def retire(self, stream_id):
        """Forget a lifecycle retired by the owner, not merely an ended input."""
        self._streams.pop(stream_id, None)

    @staticmethod
    def _direction(side):
        if side == 'L':
            return 'request'

        if side == 'R':
            return 'response'

        raise ValueError('Expected side L or R')

    def _record(self, stream_id):
        if type(stream_id) is not int or not 0 < stream_id < 2**31:
            raise ValueError('Expected a nonzero HTTP/2 stream ID')

        existing = self._streams.get(stream_id)
        if existing is not None:
            return existing

        if len(self._streams) >= self._limit:
            raise ValueError('Protocol state stream limit exceeded')

        return H2StreamState(stream_id)

    def observe(self, side, parts, *, restored=False):
        """Observe complete native units atomically; never parse raw bytes.

        Incomplete units remain the responsibility of native Parts reassembly.
        Informational response headers are not the final response head. Push
        promises likewise must not be mistaken for received request messages.
        """
        direction = self._direction(side)
        candidate = self.fork()
        observed = []

        for part in parts:
            if not part.complete or part.frame_type not in (0, 1, 3):
                continue

            # Complete retained units were observed before the earlier hold.
            # An incomplete unit receives this marker only after reassembly.
            if restored and getattr(part, '_inspection_h2_observed', False):
                if getattr(part, '_inspection_side', None) != side:
                    raise ValueError('Restored HTTP/2 unit direction changed')

                if part.stream_id not in candidate._streams:
                    raise ValueError('Restored HTTP/2 stream state is missing')

                continue

            record = candidate._record(part.stream_id)

            # Cancellation changes processing state, but never claims that
            # either message was completed or published.
            if part.frame_type == 3:
                candidate._streams[part.stream_id] = replace(
                    record, reset=True,
                    request=replace(record.request, suspended=False),
                    response=replace(record.response, suspended=False),
                )
                observed.append(part)
                continue

            if record.reset:
                raise ValueError('Cannot observe content on a reset stream')

            message = getattr(record, direction)
            if part.frame_type == 1:
                if part.headers is None:
                    continue

                fields = {entry.name: entry.value for entry in part.headers.entries}
                status = fields.get(b':status')

                if status is not None and len(status) == 3 and status.startswith(b'1'):
                    continue

                if side == 'L':
                    initial = b':method' in fields
                else:
                    initial = status is not None

                if initial:
                    message = replace(message, headers_complete=True)

            # END_STREAM is a native frame fact. Local content completeness is
            # monotonic, but absence of an observed head must remain visible.
            complete = message.content_complete is True or bool(part.flags & 1)
            message = replace(message, content_complete=complete)
            candidate._streams[part.stream_id] = replace(record, **{direction: message})
            observed.append(part)

        for part in observed:
            part._inspection_h2_observed = True
            part._inspection_side = side

        self._streams = candidate._streams

    def suspend(self, stream_id, side):
        self._processing(stream_id, side, suspended=True)

    def resume(self, stream_id, side):
        self._processing(stream_id, side, suspended=False)

    def publish(self, stream_id, side):
        """Mark completed local publication, never delivery to the remote peer."""
        self._processing(stream_id, side, published=True)

    def _processing(self, stream_id, side, *, suspended=None, published=False):
        direction = self._direction(side)
        record = self._streams.get(stream_id)
        if record is None or record.reset:
            raise ValueError('Expected an observed, non-reset stream')

        message = getattr(record, direction)
        if not message.headers_complete:
            raise ValueError('Message headers are not available')

        if published:
            if message.suspended or message.content_complete is not True:
                raise ValueError('Cannot publish a suspended or incomplete message')

            message = replace(message, published=True)
        else:
            if message.published:
                raise ValueError('Cannot change suspension after publication')

            message = replace(message, suspended=suspended)

        self._streams[stream_id] = replace(record, **{direction: message})


class ProtocolStateOwner:
    """One flow deployment's local observations, restored for each callback.

    This object never owns a socket, parser or worker-global cache. The host
    stores its bounded checkpoint with the same connection's held Parts.
    """

    MAX_BYTES = 512 * 1024

    def __init__(self, session_id, checkpoint=None):
        if type(session_id) is not str or not session_id or len(session_id) > 1024:
            raise ValueError('Protocol tracking requires a bounded connection identity')

        self.session_id = session_id
        self.h1 = H1StateTable()
        self.h2 = H2StateTable()
        self._observed_h1 = set()
        self._observed_h2 = set()

        if checkpoint is not None:
            _state_object(checkpoint, ('version', 'session_id', 'http1', 'http2'))
            if type(checkpoint['version']) is not int or checkpoint['version'] != 1:
                raise ValueError('Unsupported protocol tracking checkpoint')

            if checkpoint['session_id'] != session_id:
                raise ValueError('Protocol checkpoint belongs to another connection')

            self.h1 = H1StateTable.from_checkpoint(checkpoint['http1'])
            self.h2 = H2StateTable.from_checkpoint(checkpoint['http2'])

    def observe(self, side, parts):
        parts = tuple(parts)
        retained_h1 = set()
        retained_h2 = set()

        for part in parts:
            sequence = getattr(part, '_inspection_h1_sequence', None)
            if sequence is not None:
                retained_h1.add((side, sequence))

            if getattr(part, '_inspection_h2_observed', False):
                retained_h2.add(part.stream_id)

        h1 = self.h1.fork()
        h2 = self.h2.fork()

        # Retire completed publication on the next callback, not before the
        # current script has had a chance to see its received-message snapshot.
        # Held messages cannot be retired merely because their input is complete.
        for message in h1.snapshot():
            key = (message.side, message.sequence)
            if message.published is True and not message.suspended and key not in retained_h1:
                h1.retire(*key)

        for stream in h2.snapshot():
            both_published = stream.request.published is True and stream.response.published is True
            if (stream.reset or both_published) and stream.stream_id not in retained_h2:
                h2.retire(stream.stream_id)

        h1.observe(side, parts, restored=True)
        h2.observe(side, parts, restored=True)

        self.h1 = h1
        self.h2 = h2

        for part in parts:
            sequence = getattr(part, '_inspection_h1_sequence', None)
            if sequence is not None:
                self._observed_h1.add((side, sequence))

            if getattr(part, '_inspection_h2_observed', False):
                self._observed_h2.add((side, part.stream_id))

    def finish(self, held, paused, *, known_publication):
        """Record local disposition after native result validation.

        `held` contains directional Parts restored from the resulting hold
        checkpoints, not live input. `paused` also includes queued logical
        suspension buffers. Neither fact is a statement about peer receipt.
        A raw replacement has no proven relation to input message identities.
        """
        h1_held = set()
        h2_held = set(paused)

        for side, parts in held.items():
            for part in parts:
                sequence = getattr(part, '_inspection_h1_sequence', None)
                if sequence is not None:
                    h1_held.add((side, sequence))

                if part.frame_type is not None and part.stream_id:
                    h2_held.add((side, part.stream_id))

        for key, message in list(self.h1._messages.items()):
            suspended = key in h1_held
            published = message.published

            if suspended:
                published = False
            elif (key in self._observed_h1 or message.suspended) and published is not None:
                if not known_publication:
                    published = None
                elif message.content_complete is True:
                    published = True

            self.h1._messages[key] = replace(message, suspended=suspended, published=published)

        for stream_id, stream in list(self.h2._streams.items()):
            directions = {}

            for side, name in (('L', 'request'), ('R', 'response')):
                message = getattr(stream, name)
                key = (side, stream_id)
                suspended = key in h2_held and message.headers_complete and not stream.reset
                published = message.published

                if suspended:
                    published = False
                elif (key in self._observed_h2 or message.suspended) and published is not None:
                    if not known_publication:
                        published = None
                    elif not stream.reset and message.headers_complete and message.content_complete is True:
                        published = True

                directions[name] = replace(message, suspended=suspended, published=published)

            self.h2._streams[stream_id] = replace(stream, **directions)

    def checkpoint(self):
        import json

        result = {
            'version': 1,
            'session_id': self.session_id,
            'http1': self.h1.checkpoint(),
            'http2': self.h2.checkpoint(),
        }

        if len(json.dumps(result).encode()) > self.MAX_BYTES:
            raise ValueError('Protocol tracking checkpoint exceeds 512 KiB')

        return result

"""Explicit, bounded HPACK and flow-control translation.

Only data is checkpointed. No pickle, Python globals or worker affinity.
SETTINGS are synchronized by ordered ACKs. Incomplete units require explicit hold.
Embedded before entering the sandbox; every output needs a script's translate call.
"""
try:
    import hpack as _translate_hpack
except ImportError:
    _translate_hpack = None


_H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


def _translate_informational(part, fields):
    """Recognize a non-terminal informational response, never a trailer."""
    if part.frame_type != 1 or part.flags & 1:
        return False
    pseudo = [(name, value) for name, value, _ in fields if name.startswith(b':')]
    if len(pseudo) != 1 or pseudo[0][0] != b':status':
        return False
    status = pseudo[0][1]
    return (len(status) == 3 and status.isdigit() and
            100 <= int(status) < 200 and status != b'101')


class _TranslationInput:
    """Sender windows, charged once from original callback bytes, before hold.

    The incremental cursor owns only a frame header. DATA reserves its
    entire declared payload as soon as its header is
    available. Reassembled Parts never pass through this cursor a second time.
    """
    @staticmethod
    def initial():
        return {'window': 65535, 'initial': 65535, 'acknowledged': 65535, 'owned': 0,
                'pending': [], 'streams': {}, 'header': [], 'remaining': 0,
                'preface': None}

    def __init__(self, flow):
        self.flow = flow
        for side in ('L', 'R'):
            if 'input' not in flow.state[side]:
                raise CommitException('Translate input-window checkpoint missing; reconnect')
            if 'owned' not in flow.state[side]['input']:
                raise CommitException('Translate input ownership checkpoint missing; reconnect')

    def direction(self, side):
        return self.flow.state[side]['input']

    def cancelled(self, side, stream):
        return (self.flow.cancelled(side, stream) or
                self.flow.failed(stream) or
                self.flow._contains(self.flow.state[side].get('input_cancelled', {}), stream))

    def stream(self, side, stream):
        state = self.direction(side)
        key = str(stream)
        if key not in state['streams']:
            if not stream or len(state['streams']) >= self.flow.MAX_STREAMS:
                raise CommitException('Translate input stream quota exceeded or stream zero')
            state['streams'][key] = {'window': state['initial'], 'ended': False, 'received': 0}
        return state['streams'][key]

    def debit(self, side, stream, amount, end):
        state = self.direction(side)
        if not stream:
            raise CommitException('DATA requires nonzero stream')
        if amount > state['window']:
            raise CommitException('Translate input connection window exceeded')
        state['window'] -= amount
        state['owned'] += amount
        if self.cancelled(side, stream):
            return
        if self.flow.retired(side, stream):
            raise CommitException('DATA after translated stream termination')
        entry = self.stream(side, stream)
        if entry['ended']:
            raise CommitException('DATA after translated stream termination')
        # Until ACK, bytes sent under an earlier initial window can be in
        # flight. Account against the new window, allowing that bounded debt.
        allowance = max([state['acknowledged'], state['initial']] + state['pending']) - state['initial']
        if amount and amount > entry['window'] + allowance:
            raise CommitException('Translate input stream window exceeded')
        entry['window'] -= amount
        entry['received'] += amount
        entry['ended'] = end
        reservation = self.flow.bodies(side).get(str(stream))
        if reservation and reservation['stream'] == stream:
            if entry['received'] > reservation['limit']:
                raise CommitException('Reserved H2 body exceeds encoded byte limit')
            if entry['received'] == reservation['limit'] and not end:
                raise CommitException('Reserved H2 body limit exhausted before END_STREAM')

    def receive(self, side, data):
        state = self.direction(side)
        position = 0
        while position < len(data):
            # Raw frame fixtures may omit the preface. Once its first byte is
            # seen, however, every fragmented byte must match the real preface.
            if state['preface'] is None:
                state['preface'] = 0 if side == 'L' and data[position] == 80 else len(_H2_PREFACE)
            if state['preface'] < len(_H2_PREFACE):
                if data[position] != _H2_PREFACE[state['preface']]:
                    raise CommitException('Invalid H2 input preface')
                state['preface'] += 1
                position += 1
                continue
            if state['remaining']:
                count = min(state['remaining'], len(data) - position)
                state['remaining'] -= count
                position += count
                if state['remaining']:
                    continue
                self.complete(side)
                continue
            count = min(9 - len(state['header']), len(data) - position)
            state['header'].extend(data[position:position + count])
            position += count
            if len(state['header']) < 9:
                continue
            header = bytes(state['header'])
            length = int.from_bytes(header[:3], 'big')
            kind, flags = header[3:5]
            stream = int.from_bytes(header[5:9], 'big') & self.flow.MAX_WINDOW
            if kind == 0:
                self.debit(side, stream, length, bool(flags & 1))
            elif kind == 1 and not (self.cancelled(side, stream) or self.flow.retired(side, stream)):
                entry = self.stream(side, stream)
                entry['ended'] = entry['ended'] or bool(flags & 1)
            elif kind == 4 and flags & 1:
                if length or stream or not state['pending']:
                    raise CommitException('Unexpected input SETTINGS ACK')
                state['acknowledged'] = state['pending'].pop(0)
            state['remaining'] = length
            if not length:
                self.complete(side)

    def complete(self, side):
        state = self.direction(side)
        # Remember terminal controls at receipt, even if the script holds
        # them. This affects input policing only; forwarding remains explicit.
        header = bytes(state['header'])
        kind = header[3]
        stream = int.from_bytes(header[5:9], 'big') & self.flow.MAX_WINDOW
        if kind == 3 and stream and int.from_bytes(header[:3], 'big') == 4:
            for direction in ('L', 'R'):
                self.flow._remember(direction, 'input_cancelled', stream)
        state['header'] = []

    def sent(self, side, data):
        """Observe only actual output: retained SETTINGS grant nothing yet."""
        target = 'R' if side == 'L' else 'L'
        state = self.direction(target)
        position = len(_H2_PREFACE) if data.startswith(_H2_PREFACE) else 0
        while position < len(data):
            length = int.from_bytes(data[position:position + 3], 'big')
            kind, flags = data[position + 3:position + 5]
            stream = int.from_bytes(data[position + 5:position + 9], 'big') & self.flow.MAX_WINDOW
            payload = data[position + 9:position + 9 + length]
            position += 9 + length
            if kind == 4 and not flags & 1:
                for offset in range(0, length, 6):
                    if int.from_bytes(payload[offset:offset + 2], 'big') != 4:
                        continue
                    initial = int.from_bytes(payload[offset + 2:offset + 6], 'big')
                    delta = initial - state['initial']
                    for entry in state['streams'].values():
                        if entry['window'] + delta > self.flow.MAX_WINDOW:
                            raise CommitException('Translate input window overflow after SETTINGS')
                        entry['window'] += delta
                    state['initial'] = initial
                if len(state['pending']) >= 128:
                    raise CommitException('Translate input SETTINGS quota exceeded')
                state['pending'].append(state['initial'])
            elif kind == 8:
                increment = int.from_bytes(payload, 'big') & self.flow.MAX_WINDOW
                if stream and (self.flow.retired(target, stream) or self.cancelled(target, stream)):
                    continue
                entry = self.stream(target, stream) if stream else state
                if not increment or entry['window'] + increment > self.flow.MAX_WINDOW:
                    raise CommitException('Translate input window grant overflow')
                entry['window'] += increment

    def finish(self):
        for side in ('L', 'R'):
            self.sent(side, bytes(self.flow.output[side]))
            streams = self.direction(side)['streams']
            for key in list(streams):
                if self.flow.retired(side, int(key)) or self.cancelled(side, int(key)):
                    del streams[key]


class _TranslationHoldCredit:
    MAX_BODY = 256 * 1024
    MAX_BODIES = 32
    INPUT_CAPACITY = MAX_BODY + 65535

    def __init__(self, transaction, flow, incoming, cut):
        self.flow, self.incoming = flow, incoming
        side = flow.side
        direction = flow.state[side]
        for part, limit in transaction.body_reservations:
            if flow.cancelled(side, part.stream_id) or flow.failed(part.stream_id):
                continue
            if not transaction.hold_credit_available:
                raise CommitException('Body reservation requires backend admission support')
            positions = [i for i, item in enumerate(transaction.message.parts) if item is part]
            if not positions or positions[0] < cut or not part.complete or part.frame_type != 1:
                raise CommitException('Reserve a complete initial HEADERS part in the held suffix')
            fields = transaction._header_fields(part)
            if not any(name in (b':method', b':status') for name, _, _ in fields):
                raise CommitException('Body reservation requires initial request or response headers')
            if transaction.source_informational.get(id(part), False):
                raise CommitException('Reserve the final response body, not informational headers')
            lengths = transaction.source_lengths[id(part)]
            if any(not value.isdigit() or int(value) > limit for value in lengths):
                raise CommitException('Content-Length exceeds reserved encoded body limit')
            bodies = flow.bodies(side)
            current = bodies.get(str(part.stream_id))
            if current and current['limit'] != limit:
                raise CommitException('Body reservation limit is immutable')
            if not current:
                previous = direction['streams'].get(str(part.stream_id))
                informational_only = previous is not None and previous.get('informational_only', False)
                if ((previous is not None and not informational_only) or
                        flow.retired(side, part.stream_id)):
                    raise CommitException('Body reservation requires headers retained before any output')
                candidate = {'stream': part.stream_id, 'limit': limit,
                             'stream_due': 0, 'advanced': 0}
                active = [body for body in bodies.values() if not flow.cancelled(side, body['stream'])]
                if len(active) >= self.MAX_BODIES or sum(body['limit'] for body in active) + limit > self.MAX_BODY:
                    raise CommitException('Body reservation aggregate exceeds 256 KiB or 32 streams')
                bodies[str(part.stream_id)] = candidate
                flow.state['hold_reserved'] = True
        if flow.state.get('hold_reserved') and not transaction.hold_credit_available:
            raise CommitException('Body reservation backend capability lost')
        # A reserved body is an all-or-nothing retained semantic message.
        for reservation in flow.bodies(side).values():
            if (flow.cancelled(side, reservation['stream']) or
                    flow.failed(reservation['stream'])):
                continue
            for part in transaction.message.parts[:cut]:
                if part.frame_type == 1 and part.stream_id == reservation['stream']:
                    if transaction.informational(part):
                        continue
                    if not part.content.complete:
                        raise CommitException('Reserved body must remain held until complete')

    def advance(self):
        for side in ('L', 'R'):
            direction = self.flow.state[side]
            limits = sum(body['limit'] for body in self.flow.bodies(side).values()
                         if not self.flow.cancelled(side, body['stream']))
            if self.flow.bodies(side):
                # A smaller serialized promise must also bound early connection
                # credit consumed by unrelated streams in the held suffix.
                capacity = min(self.INPUT_CAPACITY, limits + 65535)
                direction['input_capacity'] = max(direction.get('input_capacity', 0), capacity)
            for reservation in list(self.flow.bodies(side).values()):
                self.advance_body(side, reservation)
            if self.flow.bodies(side) or direction.get('advance_due', 0) or direction['input']['owned']:
                # Reserve serialized capacity, including baseline in-flight DATA,
                # base64 representations and metadata. Fragmentation still has
                # an explicit checkpoint bound. Never shrink an outstanding promise.
                capacity = direction.get('input_capacity', 65535)
                needed = min(1024 * 1024, ((3 * capacity + 65536 + 65535) // 65536) * 65536)
                direction['hold_capacity'] = max(direction.get('hold_capacity', 0), needed)
            else:
                direction.pop('hold_capacity', None)
                direction.pop('input_capacity', None)

    def advance_body(self, side, reservation):
        direction = self.flow.state[side]
        stream = reservation['stream']
        if self.flow.failed(stream):
            # A staged local failure consumes the upstream reset and owns the
            # downstream result. No future body bytes can satisfy this stream's
            # reservation, and unused stream credit dies with the stream.
            del self.flow.bodies(side)[str(stream)]
            return
        if self.incoming.cancelled(side, stream):
            if self.flow.cancelled(side, stream) and side in self.flow.disposed:
                if reservation['stream_due']:
                    raise CommitException('Cancelled body credit did not settle')
                del self.flow.bodies(side)[str(stream)]
                return
            # Only a fully accepted original body has no retained Parts to
            # dispose of in another callback direction. Output cancellation
            # has already discarded its DATA and settled ownership in finish().
            elif reservation.get('released') and not reservation['stream_due']:
                if self.flow.cancelled(side, stream):
                    del self.flow.bodies(side)[str(stream)]
                # A retained reset affects input policing before forwarding.
                # Keep the reservation until that reset is actually accepted.
                return
            else:
                raise CommitException('Reserved H2 body cancelled; strict teardown releases reservation')
        if self.flow.retired(side, stream):
            if reservation['stream_due']:
                raise CommitException('Reserved H2 body credit did not settle')
            del self.flow.bodies(side)[str(stream)]
            return
        state = self.incoming.direction(side)
        entry = state['streams'][str(stream)]
        received, limit = entry['received'], reservation['limit']
        if received > limit or (received == limit and not entry['ended']):
            raise CommitException('Reserved H2 body limit exhausted before completion')
        if entry['ended']:
            return
        owned_output = sum(item.get('owned', 0) for item in direction['streams'].values())
        held = state['owned'] - owned_output
        room = direction['input_capacity'] - state['owned'] - state['window']
        if room < 0:
            raise CommitException('H2 input exceeds admitted reservation capacity')
        connection_grant = min(held - direction.get('advance_due', 0), room)
        allowance = max([state['acknowledged'], state['initial']] + state['pending']) - state['initial']
        stream_room = max(0, limit - received - max(0, entry['window'] + allowance))
        stream_grant = min(received - reservation['advanced'], stream_room)
        target = 'R' if side == 'L' else 'L'
        for stream_id, amount in ((0, connection_grant), (stream, stream_grant)):
            if amount < 0:
                raise CommitException('Reserved H2 credit provenance underflow')
            if amount:
                self.flow.output[target].extend(self.flow.frame(8, 0, stream_id, amount.to_bytes(4, 'big')))
        state['window'] += connection_grant
        entry['window'] += stream_grant
        direction['advance_due'] = direction.get('advance_due', 0) + connection_grant
        reservation['stream_due'] += stream_grant
        reservation['advanced'] += stream_grant
        if state['window'] <= 0 or entry['window'] + allowance <= 0:
            raise CommitException('Reserved H2 input capacity exhausted before completion')


class _TranslationFlow:
    """Two independent credit ledgers, advanced only by explicit translation.

    Input credit belongs to the sender; output credit belongs to the recipient.
    Recipient WINDOW_UPDATEs never pass through after we own flow control.
    Consumed input is acknowledged after that stream's queued DATA drains.
    The checkpoint contains owned bytes, never live Python references.
    """
    MAX_WINDOW = 0x7fffffff
    MAX_PENDING = 384 * 1024
    MAX_STREAMS = 1024
    MAX_RANGES = 1024

    @staticmethod
    def initial():
        def direction():
            return {'output': 65535, 'initial': 65535,
                    'frame': 16384, 'streams': {}, 'queue': [], 'credit': 0,
                    'input': _TranslationInput.initial()}
        state = {'version': 1, 'L': direction(), 'R': direction()}
        state['R']['input']['preface'] = len(_H2_PREFACE)
        return state

    def __init__(self, state, side):
        import base64
        self.state = state
        self.side = side
        self.peer = 'R' if side == 'L' else 'L'
        self.output = {'L': bytearray(), 'R': bytearray()}
        self.disposed = set()
        self.queues = {key: [base64.b64decode(value, validate=True)
                             for value in state[key]['queue']] for key in ('L', 'R')}
        for key in ('L', 'R'):
            # Upgrade the original single-body checkpoint without losing debt.
            old = state[key].pop('body', None)
            if old:
                self.bodies(key)[str(old['stream'])] = old
                state[key]['hold_capacity'] = 1024 * 1024
                state[key]['input_capacity'] = _TranslationHoldCredit.INPUT_CAPACITY

    def bodies(self, side):
        return self.state[side].setdefault('bodies', {})

    def http_streams(self):
        """Connection-wide HTTP lifecycle records, independent of DATA credit."""
        return self.state.setdefault('http_streams', {})

    def observe_request(self, stream, ended):
        records = self.http_streams()
        key = str(stream)
        if key not in records:
            if not stream or not stream & 1 or len(records) >= self.MAX_STREAMS:
                raise CommitException('Translate HTTP request stream quota exceeded')
            records[key] = {
                'request_headers': True,
                'request_ended': bool(ended),
                'final_response': False,
                'failure_staged': False,
            }
            return
        record = records[key]
        record['request_headers'] = True
        record['request_ended'] = record.get('request_ended', False) or bool(ended)

    def observe_request_end(self, stream):
        record = self.http_streams().get(str(stream))
        if record is not None:
            record['request_ended'] = True

    def observe_final_response(self, stream):
        record = self.http_streams().get(str(stream))
        if record is not None:
            record['final_response'] = True
            del self.http_streams()[str(stream)]

    def failed(self, stream):
        return self._contains(self.state.get('failed_streams', {}), stream)

    def fail_stream(self, stream):
        records = self.http_streams()
        record = records.get(str(stream))
        if record is None or record.get('failure_staged'):
            raise CommitException('Pending request stream is no longer publishable')
        record['failure_staged'] = True
        self._remember_connection('failed_streams', stream)
        del records[str(stream)]
        self.close('L', stream)

    def _remember_connection(self, name, stream):
        ranges = self.state.setdefault(name, {})
        parity = str(stream & 1)
        merged = []
        for first, last in sorted(ranges.get(parity, []) + [[stream, stream]]):
            if merged and first <= merged[-1][1] + 2:
                merged[-1][1] = max(merged[-1][1], last)
            else:
                merged.append([first, last])
        ranges[parity] = merged
        if sum(map(len, ranges.values())) > self.MAX_RANGES:
            raise CommitException('Translate failed stream range quota exceeded')

    def stream(self, side, stream):
        streams = self.state[side]['streams']
        key = str(stream)

        if key not in streams:
            if self.retired(side, stream):
                raise CommitException('DATA after translated stream termination')
            if not stream or len(streams) >= self.MAX_STREAMS:
                raise CommitException('Translate flow stream quota exceeded or stream zero')
            initial = self.state[side]['initial']
            streams[key] = {'output': initial, 'credit': 0, 'closed': False,
                            'content_length': False}

        return streams[key]

    @staticmethod
    def _contains(ranges, stream):
        return any(first <= stream <= last for first, last in ranges.get(str(stream & 1), []))

    def _remember(self, side, name, stream):
        # IDs increase by two per initiator. Merge adjacent closed intervals;
        # sequential churn costs constant space without forgetting late frames.
        ranges = self.state[side].setdefault(name, {})
        parity = str(stream & 1)
        merged = []
        for first, last in sorted(ranges.get(parity, []) + [[stream, stream]]):
            if merged and first <= merged[-1][1] + 2:
                merged[-1][1] = max(merged[-1][1], last)
            else:
                merged.append([first, last])
        ranges[parity] = merged
        if sum(map(len, ranges.values())) > self.MAX_RANGES:
            raise CommitException('Translate closed stream range quota exceeded')

    def retired(self, side, stream):
        return self._contains(self.state[side].get('retired', {}), stream)

    def cancelled(self, side, stream):
        if self._contains(self.state[side].get('cancelled', {}), stream):
            return True
        for sender in ('L', 'R'):
            last = self.state[sender].get('goaway')
            if last is not None and stream & 1 == (sender == 'R') and stream > last:
                return True
        return False

    def close(self, side, stream):
        entry = self.state[side]['streams'].get(str(stream))
        if entry is not None:
            entry['closed'] = True
        else:
            self._remember(side, 'retired', stream)

    def settings(self, part):
        if part.flags & 1:
            return

        # A received SETTINGS constrains what we may send back to its sender.
        direction = self.state[self.peer]
        data = bytes(part._data)

        for offset in range(0, len(data), 6):
            key = int.from_bytes(data[offset:offset + 2], 'big')
            value = int.from_bytes(data[offset + 2:offset + 6], 'big')

            if key == 4:
                delta = value - direction['initial']
                for stream in direction['streams'].values():
                    if stream['output'] + delta > self.MAX_WINDOW:
                        raise CommitException('Translate stream window overflow after SETTINGS')
                    stream['output'] += delta
                direction['initial'] = value
            elif key == 5:
                direction['frame'] = value

    def update(self, part):
        data = bytes(part._data)

        if len(data) != 4:
            raise CommitException('WINDOW_UPDATE requires four bytes')

        increment = int.from_bytes(data, 'big') & self.MAX_WINDOW
        direction = self.state[self.peer]
        if not increment:
            raise CommitException('WINDOW_UPDATE increment must be nonzero')
        if part.stream_id and (self.retired(self.peer, part.stream_id) or
                               self.cancelled(self.peer, part.stream_id)):
            return
        target = self.stream(self.peer, part.stream_id) if part.stream_id else direction
        if target.get('closed'):
            return  # Late credit for our already emitted END_STREAM is harmless.
        if target['output'] + increment > self.MAX_WINDOW:
            raise CommitException('Translate flow-control window overflow')

        target['output'] += increment

    def reset(self, part):
        if not part.stream_id or len(part._data) != 4:
            raise CommitException('Invalid RST_STREAM')

        for side in ('L', 'R'):
            self._remember(side, 'cancelled', part.stream_id)
            self.close(side, part.stream_id)
        self.discard_cancelled()

    def terminate(self, stream, target, error_code):
        """Cancel a local stream and emit its reset without idle suppression.

        reset() handles a peer-originated RST_STREAM and may suppress forwarding
        when the peer has never seen a locally initiated stream.  A local
        termination is the operation that makes the cancellation observable,
        so it intentionally has separate publication semantics.
        """
        if target not in ('L', 'R'):
            raise CommitException('Invalid H2 termination target')
        if type(stream) is not int or not 0 < stream <= self.MAX_WINDOW:
            raise CommitException('Invalid H2 termination stream')
        if type(error_code) is not int or not 0 <= error_code <= 0xffffffff:
            raise CommitException('Invalid H2 termination error code')
        if any(self.cancelled(side, stream) for side in ('L', 'R')):
            raise CommitException('H2 termination stream is already cancelled')

        for side in ('L', 'R'):
            self._remember(side, 'cancelled', stream)
            self.close(side, stream)
        self.discard_cancelled()
        self.output[target].extend(self.frame(
            3,
            0,
            stream,
            error_code.to_bytes(4, 'big'),
        ))

    def discard_input(self, side, stream_id, amount):
        direction = self.state[side]
        advanced = min(amount, direction.get('advance_due', 0))
        direction['advance_due'] = direction.get('advance_due', 0) - advanced
        direction['credit'] += amount - advanced
        direction['cancelled_owned'] = direction.get('cancelled_owned', 0) + amount
        reservation = self.bodies(side).get(str(stream_id))
        if reservation and reservation['stream'] == stream_id:
            reservation['stream_due'] -= min(amount, reservation['stream_due'])

    def discard_cancelled(self):
        for side in ('L', 'R'):
            # Encoded headers must still reach the peer's HPACK decoder, even
            # on cancelled streams. Never drop/reorder those compression units.
            self.queues[side] = [wire for wire in self.queues[side]
                                 if wire[3] != 0 or not self.cancelled(
                                     side, int.from_bytes(wire[5:9], 'big') & self.MAX_WINDOW)]
            for key, entry in self.state[side]['streams'].items():
                if self.cancelled(side, int(key)):
                    entry['closed'] = True

    def goaway(self, part):
        if part.stream_id or len(part._data) < 8:
            raise CommitException('Invalid GOAWAY')
        last = int.from_bytes(part._data[:4], 'big') & self.MAX_WINDOW
        previous = self.state[self.side].get('goaway', self.MAX_WINDOW)
        if last > previous:
            raise CommitException('GOAWAY last stream ID must not increase')
        self.state[self.side]['goaway'] = last
        self.discard_cancelled()

    def consume_failed_goaway(self, part):
        """Remember a consumed upstream GOAWAY without rejecting its streams."""
        if part.stream_id or len(part._data) < 8:
            raise CommitException('Invalid GOAWAY')
        last = int.from_bytes(part._data[:4], 'big') & self.MAX_WINDOW
        previous = self.state.get('failed_goaway', {}).get('last_stream_id', self.MAX_WINDOW)
        if last > previous:
            raise CommitException('GOAWAY last stream ID must not increase')
        self.state['failed_goaway'] = {
            'last_stream_id': last,
            'error_code': int.from_bytes(part._data[4:8], 'big'),
            'additional_data': bytes(part._data[8:]).hex(),
        }

    def accept(self, part, wire):
        side = self.side
        kind = part._initial[0]

        if kind == 8:
            self.update(part)
            return
        if kind == 4:
            self.settings(part)
        if kind == 3:
            # A locally initiated stream whose original headers are still held
            # does not exist at the recipient. Do not send RST_STREAM on idle.
            initiated = part.stream_id & 1 == (side == 'L')
            queued = any(item[3] == 1 and int.from_bytes(item[5:9], 'big') & self.MAX_WINDOW == part.stream_id
                         for item in self.queues[side] if not item.startswith(_H2_PREFACE))
            if initiated and not queued and not self._contains(self.state[side].get('opened', {}), part.stream_id):
                wire = b''
            self.reset(part)
        if kind == 7:
            self.goaway(part)

        if kind == 0:
            amount = int.from_bytes(bytes(part._wire)[:3], 'big')
            direction = self.state[side]
            if self.cancelled(side, part.stream_id) or self.failed(part.stream_id):
                self.discard_input(side, part.stream_id, amount)
                return
            # Early connection credit is backed by the retained input pool.
            # Normal release follows source order; cancellation may settle any
            # of that ownership first. Stream credit has its separate debt.
            advanced = min(amount, direction.get('advance_due', 0))
            direction['advance_due'] = direction.get('advance_due', 0) - advanced
            direction['credit'] += amount - advanced
            stream = self.stream(side, part.stream_id)
            stream['informational_only'] = False
            if stream['closed'] or stream.get('ended'):
                raise CommitException('DATA after translated stream termination')
            stream['ended'] = bool(part.flags & 1)
            # Include padding and its length byte, but not the frame header.
            stream['owned'] = stream.get('owned', 0) + amount
            reservation = self.bodies(side).get(str(part.stream_id))
            advanced_stream = 0
            if reservation and reservation['stream'] == part.stream_id:
                advanced_stream = min(amount, reservation['stream_due'])
                reservation['stream_due'] -= advanced_stream
                if part.flags & 1:
                    reservation['released'] = True
            # Per-stream refund debt can differ from connection debt when
            # several streams contribute bytes to the same retained prefix.
            stream['connection_credit'] = stream.get('connection_credit', 0) + amount - advanced
            stream['credit'] += amount - advanced_stream

            if part.flags & 1 and side == 'L':
                self.observe_request_end(part.stream_id)

        if kind == 1 and part.flags & 1 and not self.cancelled(side, part.stream_id):
            if not self.retired(side, part.stream_id):
                self.stream(side, part.stream_id)['ended'] = True
            reservation = self.bodies(side).get(str(part.stream_id))
            if reservation and reservation['stream'] == part.stream_id:
                reservation['released'] = True

        # Control frames must not wait behind DATA whose credit they enable.
        # Header blocks stay indivisible; queued output never ends mid-block.
        # ACK is a synchronization boundary for HPACK and frame-size limits.
        # It must remain behind previously encoded header blocks.
        if kind in (6, 7, 8) or (kind == 4 and not part.flags & 1):
            self.output[side].extend(wire)
        elif wire:
            self.queues[side].append(wire)

        self.drain(side)

    def drain(self, side):
        queue = self.queues[side]
        direction = self.state[side]

        while queue:
            # Pick one frame per ready stream per round. Preserve each stream's
            # order and global HPACK order; SETTINGS ACK and other non-header
            # control units remain synchronization barriers.
            candidates, seen = [], set()
            header_seen = False
            for index, item in enumerate(queue):
                if item.startswith(_H2_PREFACE) or item[3] not in (0, 1):
                    if index == 0:
                        candidates.append((index, 0))
                    break
                stream_id = int.from_bytes(item[5:9], 'big') & self.MAX_WINDOW
                blocked = stream_id in seen
                seen.add(stream_id)
                if item[3] == 1:
                    blocked = blocked or header_seen
                    header_seen = True
                elif len(item) > 9 and not (item[4] & 8 and item[9] == len(item) - 10):
                    blocked = blocked or min(direction['output'], self.stream(side, stream_id)['output']) <= 0
                if not blocked:
                    candidates.append((index, stream_id))
            if not candidates:
                break
            previous = direction.get('last_sent', -1)
            index, selected = min(candidates, key=lambda entry: (entry[1] <= previous, entry[1]))
            wire = queue[index]
            direction['last_sent'] = selected
            if wire.startswith(_H2_PREFACE) or wire[3] != 0:
                self.output[side].extend(queue.pop(index))
                if not wire.startswith(_H2_PREFACE) and wire[3] == 1:
                    self._remember(side, 'opened', int.from_bytes(wire[5:9], 'big') & self.MAX_WINDOW)
                if not wire.startswith(_H2_PREFACE) and wire[3] == 1 and wire[4] & 1:
                    stream_id = int.from_bytes(wire[5:9], 'big') & self.MAX_WINDOW
                    self.close(side, stream_id)
                continue

            stream_id = int.from_bytes(wire[5:9], 'big') & self.MAX_WINDOW
            stream = self.stream(side, stream_id)
            flags = wire[4]
            payload = wire[9:]
            available = min(direction['output'], stream['output'], direction['frame'])

            if len(payload) <= available or not payload:
                self.output[side].extend(queue.pop(index))
                direction['output'] -= len(payload)
                stream['output'] -= len(payload)
                if flags & 1:
                    stream['closed'] = True
                continue

            # Padding has no application meaning. Remove it only when a frame
            # needs reframing; untouched, immediately sendable DATA stays exact.
            if flags & 8:
                padding = payload[0]
                payload = payload[1:len(payload) - padding]
                flags &= ~8
                queue[index] = self.frame(0, flags, stream_id, payload)
                continue

            if available <= 0:
                break

            self.output[side].extend(self.frame(0, flags & ~1, stream_id, payload[:available]))
            queue[index] = self.frame(0, flags, stream_id, payload[available:])
            direction['output'] -= available
            stream['output'] -= available

    @staticmethod
    def frame(kind, flags, stream, data):
        return (len(data).to_bytes(3, 'big') + bytes((kind, flags)) +
                stream.to_bytes(4, 'big') + data)

    def finish(self):
        import base64
        self.drain(self.side)
        self.drain(self.peer)

        for side in ('L', 'R'):
            direction = self.state[side]
            target = 'R' if side == 'L' else 'L'
            blocked = {int.from_bytes(wire[5:9], 'big') & self.MAX_WINDOW
                       for wire in self.queues[side] if wire[3] == 0}
            retained = 0
            refunds = bytearray()
            for key, entry in list(direction['streams'].items()):
                stream_id = int(key)
                if stream_id in blocked:
                    retained += entry.get('connection_credit', entry['credit'])
                    continue
                amount = entry['credit']
                if amount and not entry.get('closed'):
                    refunds.extend(self.frame(8, 0, stream_id, amount.to_bytes(4, 'big')))
                entry['credit'] = 0
                entry['connection_credit'] = 0
                direction['input']['owned'] -= entry.get('owned', 0)
                entry['owned'] = 0
                if entry['closed']:
                    self._remember(side, 'retired', stream_id)
                    del direction['streams'][key]
            amount = direction['credit'] - retained
            if amount:
                self.output[target].extend(self.frame(8, 0, 0, amount.to_bytes(4, 'big')))
            self.output[target].extend(refunds)
            direction['credit'] = retained
            direction['input']['owned'] -= direction.pop('cancelled_owned', 0)
            if direction['input']['owned'] < 0:
                raise CommitException('Translate input ownership underflow; reconnect')

        pending = sum(len(wire) for queue in self.queues.values() for wire in queue)
        if pending > self.MAX_PENDING:
            raise CommitException('Translate pending output exceeds 384 KiB')
        if sum(map(len, self.output.values())) > 1024 * 1024:
            raise CommitException('Translated directional output exceeds 1 MiB')

        for side in ('L', 'R'):
            self.state[side]['queue'] = [base64.b64encode(wire).decode() for wire in self.queues[side]]

        return bytes(self.output[self.side]), bytes(self.output[self.peer])


class Mode:
    """Connection processing modes. Translate requires every callback explicitly."""
    Rewrite = 'rewrite'
    Translate = 'translate'


class ConnectionHttp2:
    """Persistent HTTP/2 policy, applied only by an explicitly returned translate result."""

    def __init__(self, connection):
        self._connection = connection

    @api_method('header: RewritePart, data: bytes, *, encoded: bool = False', 'None',
                'Replace a complete retained H2 message body, including adding DATA to a header-only message. Decoded bytes use the current Content-Encoding; encoded=True accepts already encoded entity bytes. Existing Parts and flags remain untouched. The complete message must be in the emitted prefix of the returned Translate result. Cannot combine with direct DATA or logical Body edits. Existing Content-Length is repaired.',
                'api.connection.set_mode(Mode.Translate)\nfor part in api.message.parts:\n    if part.frame_type == 1 and part.complete and part.content.complete is True:\n        api.connection.http2.replace_body(part, b"replacement")\n        break\nreturn api.message.translate()',
                availability='Live H2 flow with content-reverse from activation. Complete initial headers, body and trailers must remain available together. Native output windows, quotas and cancellation still apply.',
                access='staged complete-message body replacement')
    def replace_body(self, header, data, *, encoded=False):
        if not isinstance(data, bytes) or type(encoded) is not bool:
            raise CommitException('Body replacement requires bytes and a boolean encoded flag')
        if len(data) > 1024 * 1024:
            raise CommitException('Replacement body exceeds 1 MiB')
        transaction = self._connection._transaction()
        transaction.stage_message_edit(header, 'body', (data, encoded))

    @api_method('header: RewritePart, fields: list[HpackField] | None', 'None',
                'Replace, add or remove the trailers of a complete retained H2 message. Use literal Header fields; None removes trailers and an empty list emits an empty trailing block. Framing fields and pseudo-headers are rejected. Parts remain unchanged until explicit Translate publication; the whole message must be in the emitted prefix.',
                'api.connection.set_mode(Mode.Translate)\nfor part in api.message.parts:\n    if part.frame_type == 1 and part.complete and part.content.complete is True:\n        api.connection.http2.replace_trailers(part, [api.http2.Header(b"x-test", b"done")])\n        break\nreturn api.message.translate()',
                availability='Live H2 flow with content-reverse from activation. Complete initial headers, body and trailers must remain available together.',
                access='staged complete-message trailer replacement')
    def replace_trailers(self, header, fields):
        copied = None
        if fields is not None:
            copied = []
            size = 0
            for field in fields:
                if (not isinstance(field, HpackField) or not isinstance(field.name, bytes) or
                        not isinstance(field.value, bytes) or field.index or field.name_index or
                        field.indexing not in ('without', 'incremental', 'never')):
                    raise CommitException('Trailers require literal Header fields')
                name = field.name
                if (re.fullmatch(rb"[!#$%&'*+.^_`|~0-9a-z-]+", name) is None or
                        name in (b'content-length', b'transfer-encoding', b'host',
                                 b'connection', b'te', b'trailer', b'upgrade')):
                    raise CommitException('Invalid trailer name or framing field')
                if any(byte in name for byte in (b'\r', b'\n', b'\x00')) or any(
                        byte in field.value for byte in (b'\r', b'\n', b'\x00')):
                    raise CommitException('Invalid control byte in trailers')
                copied.append((name, field.value, field.indexing == 'never'))
                size += len(name) + len(field.value) + 32
                if size > 65536:
                    raise CommitException('Replacement trailers exceed 64 KiB')
        transaction = self._connection._transaction()
        transaction.stage_message_edit(header, 'trailers', copied)

    @api_method('header: RewritePart, max_bytes: int', 'None',
                'Reserve bounded input capacity for a retained H2 body and advance credit only during explicit Translate. Keep the initial header held until the complete body is available, including END_STREAM trailers. Limits count original encoded DATA including padding and are immutable: at most 32 reservations and 256 KiB combined per direction. Backend capacity is released after both directions settle their reserved bodies, input ownership and early credit.',
                'api.connection.set_mode(Mode.Translate)\nfor part in api.message.parts:\n    if part.type == PartType.Http2.Header and part.complete and part.content.complete is False:\n        api.message.parts.hold_from(part)\n        api.connection.http2.reserve_body(part, 128 * 1024)\n        break\nreturn api.message.translate()',
                availability='Live sole flow deployment with backend reservation support and content-reverse. RST_STREAM and GOAWAY bypass body hold during explicit Translate, dispose cancelled DATA and preserve source HPACK history. Exhausted capacity still tears down strict translation.',
                access='staged body reservation')
    def reserve_body(self, header, max_bytes):
        if type(max_bytes) is not int or not 0 < max_bytes <= _TranslationHoldCredit.MAX_BODY:
            raise CommitException('Body reservation limit must be an integer in 1..262144')
        transaction = self._connection._transaction()
        if 'flow' not in transaction.control_before:
            raise CommitException('Body reservation requires content-reverse from activation')
        transaction.body_reservations = [(part, limit) for part, limit in transaction.body_reservations
                                         if part is not header] + [(header, max_bytes)]

    @api_method(
        'request_part: RewritePart, *, status: int = 100, '
        'headers: list[tuple[bytes, bytes]] = ()',
        'int',
        'Stage one protocol-owned informational response for a callback-local '
        'H2 request. The response is emitted in the reverse direction without '
        'ending the stream. Publication and both HPACK checkpoints remain '
        'atomic until message.translate().',
        'api.connection.set_mode(Mode.Translate)\n'
        'request = next(part for part in api.message.parts '
        'if part.frame_type == 1 and part.complete)\n'
        'stream = api.connection.http2.emit_informational_response(\n'
        '    request, status=100,\n'
        ')\n'
        'api.print("Continued stream", stream)\n'
        'return api.message.translate()',
        availability='Live client-to-server H2 flow with content-reverse from '
        'activation. The anchor must be callback-local complete initial request '
        'HEADERS. Status 101, bodies, trailers and END_STREAM are not supported.',
        access='staged reverse informational response',
    )
    def emit_informational_response(self, request_part, *, status=100, headers=()):
        transaction = self._connection._transaction()
        return transaction.stage_informational_response(
            request_part,
            status,
            headers,
        )

    @api_method(
        'response_part: RewritePart',
        'int',
        'Consume one callback-local upstream informational response without '
        'publishing it downstream. The source HPACK decoder advances while the '
        'downstream encoder remains unchanged. Publication stays atomic until '
        'message.translate().',
        'api.connection.set_mode(Mode.Translate)\n'
        'for part in api.message.parts:\n'
        '    fields = () if part.headers is None else part.headers.entries\n'
        '    informational = any(\n'
        '        field.name == b":status" and field.value[:1] == b"1"\n'
        '        for field in fields\n'
        '    )\n'
        '    if part.frame_type == 1 and part.complete and informational:\n'
        '        api.connection.http2.suppress_informational_response(part)\n'
        'return api.message.translate()',
        availability='Live server-to-client H2 flow with content-reverse from '
        'activation. The anchor must be an original complete informational '
        'HEADERS block in the prefix published by this Translate result.',
        access='staged informational response suppression',
    )
    def suppress_informational_response(self, response_part):
        transaction = self._connection._transaction()
        return transaction.stage_informational_suppression(response_part)

    @api_method(
        'goaway_part: RewritePart, *, status: int = 502, '
        'headers: list[tuple[bytes, bytes]] = (), body: bytes = b"", '
        'trailers: list[tuple[bytes, bytes]] = (), '
        'include_content_length: bool = True',
        'tuple[int, ...]',
        'Replace every observed client request still awaiting final response '
        'when this upstream GOAWAY arrived. The GOAWAY is consumed, selected '
        'streams receive protocol-owned responses, and later source frames for '
        'those streams are discarded. Publication remains atomic until '
        'message.translate().',
        'api.connection.set_mode(Mode.Translate)\n'
        'goaway = next((part for part in api.message.parts '
        'if part.frame_type == 7 and part.complete), None)\n'
        'if goaway is not None:\n'
        '    failed = api.connection.http2.fail_pending_requests(\n'
        '        goaway,\n'
        '        status=502,\n'
        '        headers=[(b"content-type", b"text/plain")],\n'
        '        body=b"upstream connection closed",\n'
        '    )\n'
        '    api.print("Failed streams", failed)\n'
        '    return api.message.translate()',
        availability='Live server-to-client H2 flow with content-reverse from '
        'activation. The anchor must be a complete callback-local GOAWAY. '
        'Existing flow-control, HPACK and aggregate output limits apply.',
        access='staged connection failure response',
    )
    def fail_pending_requests(
            self,
            goaway_part,
            *,
            status=502,
            headers=(),
            body=b'',
            trailers=(),
            include_content_length=True,
    ):
        if type(include_content_length) is not bool:
            raise CommitException('include_content_length must be a boolean')
        transaction = self._connection._transaction()
        return transaction.stage_pending_request_failures(
            goaway_part,
            status,
            headers,
            body,
            trailers,
            include_content_length,
        )

    @api_method(
        'reset_part: RewritePart, *, status: int = 502, '
        'headers: list[tuple[bytes, bytes]] = (), body: bytes = b"", '
        'trailers: list[tuple[bytes, bytes]] = (), '
        'include_content_length: bool = True',
        'int',
        'Consume one complete upstream RST_STREAM and replace it with a '
        'protocol-owned failure response for the pending request on that '
        'stream. Later source frames are discarded. Publication remains '
        'atomic until message.translate().',
        'api.connection.set_mode(Mode.Translate)\n'
        'reset = next((part for part in api.message.parts '
        'if part.frame_type == 3 and part.complete), None)\n'
        'if reset is not None:\n'
        '    stream = api.connection.http2.fail_reset_stream(\n'
        '        reset,\n'
        '        status=502,\n'
        '        headers=[(b"content-type", b"text/plain")],\n'
        '        body=b"upstream stream failed",\n'
        '    )\n'
        '    api.print("Failed stream", stream)\n'
        '    return api.message.translate()',
        availability='Live server-to-client H2 flow with content-reverse from '
        'activation. The anchor must be a complete callback-local RST_STREAM '
        'for an observed request without a final response.',
        access='staged stream failure response',
    )
    def fail_reset_stream(
            self,
            reset_part,
            *,
            status=502,
            headers=(),
            body=b'',
            trailers=(),
            include_content_length=True,
    ):
        if type(include_content_length) is not bool:
            raise CommitException('include_content_length must be a boolean')
        transaction = self._connection._transaction()
        return transaction.stage_reset_stream_failure(
            reset_part,
            status,
            headers,
            body,
            trailers,
            include_content_length,
        )

    @api_method('limit: int', 'None',
                'Enforce a maximum HPACK table capacity in both directions. Idempotent; never increases a peer-advertised limit. SETTINGS and synthetic ACK handling occur only through message.translate().',
                'api.connection.set_mode(Mode.Translate)\napi.connection.http2.enforce_header_table_limit(0)\nreturn api.message.translate()',
                availability='Live H2 flow deployment; requires Translate mode. Each direction is updated on its next eligible callback, after its first SETTINGS.',
                access='staged connection policy')
    def enforce_header_table_limit(self, limit):
        if type(limit) is not int or not 0 <= limit <= 0xffffffff:
            raise CommitException('Header table limit must be an integer in 0..4294967295')

        connection = self._connection

        if not connection._requested:
            raise CommitException('Header table policy requires Mode.Translate')

        transaction = connection._transaction()
        transaction.control_before['header_limit'] = limit


@dataclass(init=False)
class Connection:
    """Connection intent is staged; setters never send or translate payloads by themselves."""
    http2: ConnectionHttp2 = documented('HTTP/2 connection policy.',
        'api.connection.set_mode(Mode.Translate)\napi.connection.http2.enforce_header_table_limit(0)\nreturn api.message.translate()',
        access='staged connection policy')

    def __init__(self, message=None, active=False, instance_mode='message', phase='content'):
        self._message = message
        self._requested = active
        self._instance_mode = instance_mode
        self._phase = phase
        self._rewrite_requested = False
        self.http2 = ConnectionHttp2(self)

    @api_method('', 'None',
                'Reserve rewrite capability before the first payload. Does not modify bytes or activate Translate. Repeated calls are harmless.',
                "if api.phase == 'setup':\n    api.connection.request_rewrite()\n    return\nreturn api.message.commit()",
                availability='Connection-start setup callback only. Easy and Expert require this permission for length changes, hold and Translate. Same-size raw replacements need no reservation and leave protocol consistency to the script.',
                access='staged setup permission')
    def request_rewrite(self):
        if self._phase != 'setup':
            raise CommitException('request_rewrite() is only allowed during connection-start setup')

        self._rewrite_requested = True

    def _transaction(self):
        transaction = getattr(self._message, '_translation', None)

        if transaction is None:
            error = getattr(self._message, '_translation_error', None)
            raise CommitException(error or 'Translate requires an eligible live H2 flow')

        if transaction.result is not None:
            raise CommitException('Set connection policy before message.translate()')

        return transaction

    @api_method('mode: str', 'None',
                'Request Mode.Translate explicitly. Requires flow instantiation and a live eligible connection. Mode.Rewrite is a no-op before activation; an active translated connection cannot revert.',
                'api.connection.set_mode(Mode.Translate)\nreturn api.message.translate()',
                availability='Live flow deployment. The returned translate result activates the mode atomically.',
                access='staged connection mode')
    def set_mode(self, mode):
        if mode == Mode.Rewrite:
            if self._requested:
                raise CommitException('Cannot return a translated connection to Rewrite')
            return

        if mode != Mode.Translate:
            raise CommitException('Expected Mode.Rewrite or Mode.Translate')

        if self._instance_mode != 'flow':
            raise CommitException('Mode.Translate requires flow instantiation')

        self._transaction()
        self._requested = True


class _TranslationSettings:
    """Shared state: a SETTINGS sender constrains the opposite direction.

    Only emitted frames publish state. Ordered ACKs delimit old in-flight
    traffic from traffic using new limits, even while either side holds Parts.
    """

    def __init__(self, saved=None, side='L'):
        import copy

        if side not in ('L', 'R'):
            raise CommitException('Translate requires an L/R side')

        self.side = side
        self.state = copy.deepcopy(saved) if saved is not None else {
            'version': 1,
            'L': {'table': 4096, 'frame': 16384, 'pending': []},
            'R': {'table': 4096, 'frame': 16384, 'pending': []},
        }

        if self.state.get('version') != 1:
            raise CommitException('Unsupported SETTINGS checkpoint')

    @property
    def limits(self):
        return self.state[self.side]

    def process(self, part, *, synthetic=False):
        """Return acknowledged changes for this direction, or None."""
        data = bytes(part._data)
        self.forward_wire = bytes(part._wire)

        if part.stream_id or len(data) % 6 or (part.flags & 1 and data):
            raise CommitException('Invalid SETTINGS frame')

        if part.flags & 1:
            queue = self.limits['pending']

            if not queue:
                raise CommitException('SETTINGS ACK has no pending peer SETTINGS')

            changes = queue.pop(0)

            if changes.get('synthetic'):
                self.forward_wire = b''  # This ACK belongs to our injected SETTINGS.

            for key in ('table', 'frame', 'push'):
                if key in changes:
                    self.limits[key] = changes[key]

            return changes

        changes = {}
        policy = self.state.get('header_limit')
        rewritten = bytearray()
        has_table = False

        for offset in range(0, len(data), 6):
            key = int.from_bytes(data[offset:offset + 2], 'big')
            value = int.from_bytes(data[offset + 2:offset + 6], 'big')

            if key == 1:
                has_table = True

                if not synthetic:
                    self.limits['advertised_table'] = value

                if policy is not None:
                    value = min(value, policy)

                changes['table'] = value
                changes['minimum'] = min(changes.get('minimum', value), value)
            elif key == 5:
                if not 16384 <= value <= 0xffffff:
                    raise CommitException('SETTINGS_MAX_FRAME_SIZE must be 16384..16777215')
                changes['frame'] = value
            elif key == 2:
                if value not in (0, 1) or (self.side == 'R' and value == 1):
                    raise CommitException('Invalid SETTINGS_ENABLE_PUSH')
                changes['push'] = value
            elif key == 4 and value > 0x7fffffff:
                raise CommitException('Invalid SETTINGS_INITIAL_WINDOW_SIZE')

            rewritten.extend(key.to_bytes(2, 'big') + value.to_bytes(4, 'big'))

        if policy is not None and not has_table:
            value = min(policy, self.limits.get('advertised_table', 4096))
            rewritten.extend(b'\x00\x01' + value.to_bytes(4, 'big'))
            changes.update(table=value, minimum=value)

        if policy is not None:
            self.limits['applied_limit'] = policy
            self.forward_wire = _h2_new_frame(4, part.flags, 0, bytes(rewritten)).commit()

        self.limits['settings_seen'] = True

        if synthetic:
            changes['synthetic'] = True

        peer = self.state['R' if self.side == 'L' else 'L']

        if len(peer['pending']) >= 64:
            raise CommitException('Too many unacknowledged SETTINGS frames')

        # Even empty/unknown-only SETTINGS consume one acknowledgment.
        peer['pending'].append(changes)
        return None

    def pending_policy_frame(self):
        """Inject only at a complete frame boundary, after this side's SETTINGS."""
        policy = self.state.get('header_limit')

        if (policy is None or not self.limits.get('settings_seen') or
                self.limits.get('applied_limit') == policy):
            return b''

        value = min(policy, self.limits.get('advertised_table', 4096))
        data = b'\x00\x01' + value.to_bytes(4, 'big')
        part = _h2_new_frame(4, 0, 0, data)
        self.process(part, synthetic=True)
        return self.forward_wire


def _translate_decoder_settings(decoder, changes):
    if changes is None or 'table' not in changes:
        return

    minimum = changes['minimum']
    pending = getattr(decoder, '_translate_minimum', None)

    if minimum < decoder.header_table.maxsize:
        decoder._translate_minimum = minimum if pending is None else min(pending, minimum)

    decoder.max_allowed_table_size = changes['table']


def _translate_decode(decoder, data):
    minimum = getattr(decoder, '_translate_minimum', None)

    if minimum is not None:
        if not data or data[0] & 0xe0 != 0x20:
            raise CommitException('Missing HPACK table-size update after SETTINGS reduction')

        size, _ = _hpack_read_integer(data, 0, 5)

        if size > minimum:
            raise CommitException('HPACK update omitted the smallest acknowledged table size')

    fields = decoder.decode(data, raw=True)
    decoder._translate_minimum = None
    return fields


def _translate_encoder_settings(encoder, changes):
    if changes is None or 'table' not in changes:
        return

    # The encoder may use less than the advertised limit. Keep its own table
    # bounded at 4096; the decoder accepts larger peer tables within quotas.
    encoder.header_table_size = min(changes['minimum'], 4096)
    encoder.header_table_size = min(changes['table'], 4096)
    updates = encoder.table_size_changes

    if updates:
        smallest, final = min(updates), updates[-1]
        encoder.table_size_changes = [smallest] if smallest == final else [smallest, final]
        encoder.header_table.resized = True


def _translate_parts(data, preface=False, settings=None):
    """Frame an established H2 direction, retaining its unfinished last unit.

    This is not protocol detection. Only translate's admitted H2 stream uses
    these boundaries; ordinary rewrite keeps using the supplied annotations.
    """
    parts, cursor = [], 0
    settings = settings or _TranslationSettings()

    if preface:
        available = min(len(data), len(_H2_PREFACE))

        if data[:available] != _H2_PREFACE[:available]:
            raise CommitException('Invalid continued H2 preface')

        part = RewritePart(data[:available], data=data[:available], complete=available == len(_H2_PREFACE))
        parts.append(part)
        cursor = available

        if not part.complete:
            part._translate_fragment = 'preface'
            return parts

    while cursor < len(data):
        start = cursor
        stream = None

        while True:
            if len(data) - cursor < 9:
                complete = False
                break

            size = int.from_bytes(data[cursor:cursor + 3], 'big')
            typ, flags = data[cursor + 3:cursor + 5]
            current_stream = int.from_bytes(data[cursor + 5:cursor + 9], 'big') & 0x7fffffff

            if size > settings.limits['frame']:
                raise CommitException('Frame exceeds acknowledged SETTINGS_MAX_FRAME_SIZE')

            if stream is not None and (typ != 9 or current_stream != stream):
                raise CommitException('Expected CONTINUATION on the held header stream')

            if stream is None and typ == 9:
                raise CommitException('Orphan CONTINUATION frame')

            end = cursor + 9 + size

            if end > len(data):
                complete = False
                break

            cursor = end

            if typ not in (1, 5, 9) or flags & 4:
                complete = True
                break

            stream = current_stream

        end = cursor if complete else len(data)

        if end - start < 9:
            part = RewritePart(data[start:end], data=data[start:end], complete=False)
        else:
            part = _h2_parse_part(memoryview(data), start, end, None)

            if complete and not part.complete:
                raise CommitException('Invalid complete H2 frame or header block')

        part.complete = complete
        part.max_frame_size = settings.limits['frame']
        parts.append(part)

        if not complete:
            part._translate_fragment = 'frame'
            break

        if part.frame_type == 4:
            settings.process(part)

    return parts


def _resume_translation(message, checkpoint, settings=None):
    """Keep complete held drafts; only rebuild the unfinished physical tail."""
    held, _ = _restore(checkpoint) if checkpoint else ([], {})
    data = message.bytes
    preface = False
    settings = settings or _TranslationSettings()
    # A cancelled partial DATA frame retains only its remaining byte count.
    # The input ledger still consumes those bytes through its physical cursor.
    discard = settings.state.get('flow', {}).get(settings.side, {}).get('discard_bytes', 0)
    data = data[min(discard, len(data)):]

    # Complete held ACKs precede fresh input and can change its frame limit.
    for part in held:
        if part.complete and part.frame_type == 4:
            settings.process(part)

    if held and not held[-1].complete:
        tail = held.pop()

        if (tail._pending is not None or tail.headers is not None or
                (tail.frame_type, tail.flags, tail.stream_id) != tail._initial):
            raise CommitException('Cannot resume an edited incomplete H2 part')

        kind = getattr(tail, '_translate_fragment', None)

        if kind not in ('frame', 'preface'):
            raise CommitException('Missing translate framing checkpoint')

        data = bytes(tail._wire) + data
        preface = kind == 'preface'

    if sum(len(p._wire) for p in held) + len(data) > 1024 * 1024:
        raise CommitException('Resumed translate message exceeds 1 MiB')

    # The first client callback may be only a prefix of the H2 preface.
    if not checkpoint and data and _H2_PREFACE.startswith(data[:len(_H2_PREFACE)]):
        preface = True

    object.__setattr__(message, 'parts', PartList(held + _translate_parts(data, preface, settings)))


def _translate_table_dump(codec):
    import base64

    table = codec.header_table
    result = {'size': table.maxsize, 'entries': [
        [base64.b64encode(name).decode(), base64.b64encode(value).decode()]
        for name, value in table.dynamic_entries
    ]}

    if hasattr(codec, 'max_allowed_table_size'):
        result['allowed'] = codec.max_allowed_table_size
        result['minimum'] = getattr(codec, '_translate_minimum', None)
    else:
        result['updates'] = list(codec.table_size_changes)

    return result


def _translate_table_load(codec, saved):
    import base64

    size = saved['size']

    if type(size) is not int or not 0 <= size <= 0xffffffff:
        raise CommitException('Invalid translate table capacity')

    codec.header_table.maxsize = size
    total = 0

    # Checkpoints list newest entries first; rebuild the table oldest first.
    for name, value in reversed(saved['entries']):
        name = base64.b64decode(name, validate=True)
        value = base64.b64decode(value, validate=True)
        total += 32 + len(name) + len(value)

        if total > size:
            raise CommitException('Translate table exceeds capacity')

        codec.header_table.add(name, value)

    codec.header_table.resized = False

    if hasattr(codec, 'max_allowed_table_size'):
        codec.max_allowed_table_size = saved.get('allowed', 4096)
        codec._translate_minimum = saved.get('minimum')
    else:
        codec.table_size_changes = list(saved.get('updates', []))
        codec.header_table.resized = bool(codec.table_size_changes)


class _TranslationMessageEdits:
    """Output-only plans; original Parts still own input credit and HPACK.

    Plans are callback-local and may only target complete emitted messages.
    Nothing is silently lost into a held checkpoint. Synthetic output passes
    through the existing queues, but must never be accepted as source DATA.
    """

    def __init__(self, transaction, flow, cut):
        import copy

        self.body_overrides = {}
        self.lengths = {}
        self.headers = {}
        self.flags = {}
        self.suppressed = set()
        self.after = {}
        if not transaction.message_edits:
            return
        if flow is None:
            raise CommitException('Message replacement requires content-reverse')

        parts = transaction.message.parts
        positions = {id(part): index for index, part in enumerate(parts)}
        by_identity = {id(part): part for part in parts}
        groups = {id(group[0]): group for group in _h2_content_groups(parts)}
        for identity, operations in transaction.message_edits.items():
            head = by_identity[identity]
            if flow.cancelled(flow.side, head.stream_id):
                continue
            group = groups.get(identity)
            if group is None:
                raise CommitException('Replacement requires a retained complete message')
            if not head.content.complete or any(not part.complete for part in group):
                raise CommitException('Replacement requires a retained complete message')
            if any(positions[id(part)] >= cut for part in group):
                raise CommitException('Emit the whole replaced message in this Translate result')
            for part in group:
                if (part.frame_type, part.flags, part.stream_id) != part._initial:
                    raise CommitException('Message replacement cannot combine with edited frame metadata')
            data = [part for part in group if part.frame_type == 0]
            trailers = [part for part in group[1:] if part.frame_type == 1]
            if len(trailers) > 1:
                raise CommitException('Message replacement found ambiguous trailers')
            trailer = trailers[0] if trailers else None
            trailer_fields = operations.get('trailers')
            have_trailer = trailer_fields is not None if 'trailers' in operations else trailer is not None
            added_data = False

            if 'body' in operations:
                if hasattr(head, '_body_plain') or any(part._pending is not None for part in data):
                    raise CommitException('Do not combine body replacement with direct DATA or Body edits')
                value, encoded = operations['body']
                wire = self._body_wire(transaction, head, data, value, encoded)
                if len(wire) > 1024 * 1024:
                    raise CommitException('Encoded replacement body exceeds 1 MiB')
                self.lengths[identity] = str(len(wire)).encode()
                offset = 0
                for index, part in enumerate(data):
                    end = len(wire) if index == len(data) - 1 else min(len(wire), offset + len(part._data))
                    replacement = wire[offset:end]
                    if replacement != bytes(part._data):
                        draft = copy.copy(part)
                        draft.set_bytes(replacement)
                        self.body_overrides[id(part)] = draft
                    offset = end
                if not data and wire:
                    flags = 0 if have_trailer else 1
                    self.after.setdefault(identity, []).append((0, flags, head.stream_id, wire))
                    added_data = True

            # Only the output's END_STREAM moves. Input termination and credit
            # are still derived from the original unchanged Parts in accept().
            self.flags[identity] = head.flags & ~1 if data or added_data or have_trailer else head.flags | 1
            if data:
                last = data[-1]
                self.flags[id(last)] = last.flags & ~1 if have_trailer else last.flags | 1

            if 'trailers' in operations:
                if trailer_fields is None:
                    if trailer is not None:
                        self.suppressed.add(id(trailer))
                elif trailer is not None:
                    self.headers[id(trailer)] = trailer_fields
                else:
                    tail = data[-1] if data else head
                    self.after.setdefault(id(tail), []).append((1, 5, head.stream_id, trailer_fields))

    @staticmethod
    def _body_wire(transaction, head, data, value, encoded):
        if encoded:
            return value
        fields = transaction._header_fields(head)
        coding = _body_encoding([item.decode('ascii', 'replace') for name, item, _ in fields
                                 if name == b'content-encoding'])
        if not coding or coding == 'identity':
            return value
        if coding not in ('gzip', 'deflate'):
            raise CommitException('Decoded body replacement supports one gzip or deflate coding')
        original = b''.join(bytes(part._data) for part in data)
        source_coding = _body_encoding([field.value.decode('ascii', 'replace')
                                       for field in transaction.decoded[id(head)].entries
                                       if field.name == b'content-encoding'])
        if original and source_coding == coding:
            import copy
            return _encode_body(copy.copy(head), original, value, coding, True)
        import zlib
        encoder = zlib.compressobj(wbits=31 if coding == 'gzip' else 15)
        return encoder.compress(value) + encoder.flush()

    def emit_after(self, part, encoder, settings, flow):
        for kind, flags, stream, payload in self.after.get(id(part), ()):
            if flow.cancelled(flow.side, stream):
                continue
            if kind == 1:
                header = _h2_new_frame(1, flags, stream, b'')
                header.max_frame_size = settings.limits['frame']
                wire = header._assemble(encoder.encode(payload))
            else:
                wire = flow.frame(kind, flags, stream, payload)
            # This is output only: accept() would invent input ownership and
            # WINDOW_UPDATE refunds for bytes the sender never transmitted.
            flow.queues[flow.side].append(wire)
            flow.drain(flow.side)


class _Translation:
    def __init__(self, message, checkpoint, peer_checkpoint, active, control=None,
                 side='L', reverse_capable=False):
        if _translate_hpack is None:
            raise CommitException('H2 translate requires python-hpack')

        self.message = message
        self.decoder = _translate_hpack.Decoder()
        self.encoder = _translate_hpack.Encoder()
        self.result = None
        self.checkpoint = None
        self.peer_checkpoint_before = peer_checkpoint
        self.peer_checkpoint = peer_checkpoint
        self.peer_checkpoint_changed = False
        self.control_checkpoint = None
        self.reverse_output = b''
        self.flow_summary = None
        self.body_reservations = []
        self.message_edits = {}
        self.local_responses = {}
        self.informational_responses = {}
        self.informational_suppressions = {}
        self.terminations = {}
        self.pending_failures = None
        self.reset_failures = {}
        self.hold_credit_available = False
        self.peer_hold_known = False
        self.peer_hold = None
        self.peer_hold_result = None
        self.peer_hold_changed = False
        self.control_before = _TranslationSettings(control, side).state
        if control is None and reverse_capable:
            self.control_before['flow'] = _TranslationFlow.initial()
        if 'flow' in self.control_before and not reverse_capable:
            raise CommitException('Translate lost content-reverse capability')
        self.settings = _TranslationSettings(control, side)
        self.decoded = {}
        self.source_lengths = {}
        self.source_informational = {}
        self.original_fields = {}
        self.originals = tuple(bytes(p._wire) for p in message.parts)
        self.identities = tuple(id(p) for p in message.parts)

        if checkpoint is not None:
            if checkpoint.get('version') != 1:
                raise CommitException('Unsupported translate checkpoint')

            _translate_table_load(self.decoder, checkpoint['input'])
            _translate_table_load(self.encoder, checkpoint['output'])

        self.peer_encoder = _translate_hpack.Encoder()
        if peer_checkpoint is not None:
            if peer_checkpoint.get('version') != 1:
                raise CommitException('Unsupported peer translate checkpoint')
            _translate_table_load(self.peer_encoder, peer_checkpoint['output'])

        self.input_before = _translate_table_dump(self.decoder)

        for part in message.parts:
            if not part.complete:
                continue  # Only an explicit hold may publish this unfinished unit.

            if part.type == PartType.Opaque:
                if part.get_bytes() != _H2_PREFACE:
                    raise CommitException('Translate requires annotated H2 frames; unknown bytes cannot be skipped')
                continue
            if part.frame_type == 9:
                raise CommitException('Orphan CONTINUATION frame')
            if part.frame_type == 4:
                _translate_decoder_settings(self.decoder, self.settings.process(part))
            if part.frame_type == 5:
                self._validate_push(part)
            if part.frame_type in (1, 5):
                # PUSH_PROMISE shares this direction's HPACK context with
                # HEADERS, including responses on the promised stream.
                self._decode_headers(part, active)

        flow = self.control_before.get('flow')
        if flow is not None:
            ledger = _TranslationFlow(flow, side)
            for part in message.parts:
                if (part.complete and part.stream_id and
                        (ledger.cancelled(side, part.stream_id) or
                         ledger.failed(part.stream_id))):
                    # Compression history is retained, but a cancelled message
                    # must not look like a body still waiting for more DATA.
                    part._translate_cancelled = True
        object.__setattr__(message, '_body_sizes', {
            id(group[0]): sum(len(p._data) for p in group if p.frame_type == 0)
            for group in _h2_content_groups(message.parts)
        })

    def informational(self, part):
        # Source and draft must agree. Editing final headers into a 1xx status
        # must not bypass the reservation's before-output admission rule.
        if self.settings.side != 'R' or not self.source_informational.get(id(part), False):
            return False
        return _translate_informational(part, self._header_fields(part))

    def stage_message_edit(self, header, operation, value):
        if 'flow' not in self.control_before:
            raise CommitException('Message replacement requires content-reverse from activation')
        if not any(part is header for part in self.message.parts):
            raise CommitException('Replacement header must belong to the current message')
        if header.frame_type != 1 or not header.complete or header.headers is None:
            raise CommitException('Replacement requires complete initial HEADERS')
        if id(header) in self.terminations:
            raise CommitException('A terminated message cannot also be replaced')
        if id(header) in self.informational_suppressions:
            raise CommitException('A suppressed informational response cannot also be replaced')
        fields = self._header_fields(header)
        if not any(name in (b':method', b':status') for name, _, _ in fields):
            raise CommitException('Replacement requires initial request or response headers')
        operations = self.message_edits.setdefault(id(header), {})
        operations[operation] = value

    @staticmethod
    def _response_fields(
            fields,
            *,
            trailers=False,
            content_length=None,
            include_content_length=True,
    ):
        """Validate response fields while retaining application field order.

        A local response owns its framing, so an application-supplied
        Content-Length is never trusted.  Keeping the first field in place and
        replacing its value preserves observable header order without allowing
        duplicate or inconsistent lengths onto the wire.
        """
        copied = []
        size = 0
        length_seen = False
        forbidden = {
            b'connection', b'host', b'keep-alive', b'proxy-connection',
            b'te', b'trailer', b'transfer-encoding', b'upgrade',
        }
        if trailers:
            forbidden.add(b'content-length')

        try:
            items = tuple(fields)
        except TypeError as error:
            raise CommitException('Response fields must be an iterable of byte pairs') from error

        for item in items:
            if (not isinstance(item, (tuple, list)) or len(item) != 2 or
                    not isinstance(item[0], bytes) or not isinstance(item[1], bytes)):
                raise CommitException('Response fields must be byte pairs')
            name, value = item
            if (not name or name.startswith(b':') or
                    re.fullmatch(rb"[!#$%&'*+.^_`|~0-9a-z-]+", name) is None or
                    name in forbidden):
                raise CommitException('Invalid HTTP/2 response field name')
            if any(byte in value for byte in (b'\r', b'\n', b'\x00')):
                raise CommitException('Invalid control byte in response field')
            if name == b'content-length':
                if not include_content_length:
                    continue
                if content_length is not None:
                    if not length_seen:
                        copied.append((name, content_length, False))
                        length_seen = True
                else:
                    copied.append((name, value, False))
            else:
                copied.append((name, value, False))
            size += len(name) + len(value) + 32
            if size > 65536:
                raise CommitException('Response fields exceed 64 KiB')
        if include_content_length and content_length is not None and not length_seen:
            copied.append((b'content-length', content_length, False))
        return tuple(copied)

    def stage_informational_response(self, request_part, status, headers):
        """Validate and stage one reverse informational response."""
        if 'flow' not in self.control_before:
            raise CommitException(
                'Informational responses require content-reverse from activation'
            )
        if self.settings.side != 'L':
            raise CommitException(
                'An informational response must be staged while publishing a request'
            )
        if type(status) is not int or not 100 <= status <= 199 or status == 101:
            raise CommitException(
                'Informational response status must be an integer in 100..199 except 101'
            )

        positions = [
            index for index, part in enumerate(self.message.parts)
            if part is request_part
        ]
        if len(positions) != 1:
            raise CommitException(
                'Informational response request must belong to the current message'
            )
        if (not request_part.complete or request_part.frame_type != 1 or
                request_part.headers is None):
            raise CommitException(
                'Informational response requires complete initial request HEADERS'
            )

        original = self.decoded.get(id(request_part))
        original_fields = [] if original is None else [
            (field.name, field.value, False)
            for field in original.entries
        ]
        methods = [
            value for name, value, _ in original_fields
            if name == b':method'
        ]
        statuses = [
            value for name, value, _ in original_fields
            if name == b':status'
        ]
        if len(methods) != 1 or statuses:
            raise CommitException(
                'Informational response requires original request HEADERS'
            )
        if id(request_part) in self.informational_responses:
            raise CommitException(
                'A request can emit only one informational response per callback'
            )
        if id(request_part) in self.local_responses:
            raise CommitException(
                'A local final response cannot also emit an informational response'
            )
        if id(request_part) in self.terminations:
            raise CommitException(
                'A terminated request cannot emit an informational response'
            )

        regular = self._response_fields(headers, trailers=True)
        self.informational_responses[id(request_part)] = {
            'anchor': request_part,
            'stream': request_part.stream_id,
            'status': status,
            'headers': regular,
        }
        return request_part.stream_id

    def stage_informational_suppression(self, response_part):
        """Validate and stage one source informational HEADERS suppression."""
        if 'flow' not in self.control_before:
            raise CommitException(
                'Informational suppression requires content-reverse from activation'
            )
        if self.settings.side != 'R':
            raise CommitException(
                'Only an upstream informational response can be suppressed'
            )
        positions = [
            index for index, part in enumerate(self.message.parts)
            if part is response_part
        ]
        if len(positions) != 1:
            raise CommitException(
                'Informational response must belong to the current message'
            )
        if (not response_part.complete or response_part.frame_type != 1 or
                response_part.headers is None or
                not self.source_informational.get(id(response_part), False)):
            raise CommitException(
                'Suppression requires original complete informational response HEADERS'
            )
        if id(response_part) in self.informational_suppressions:
            raise CommitException(
                'An informational response can be suppressed only once per callback'
            )
        if id(response_part) in self.message_edits:
            raise CommitException(
                'A replaced response cannot also be suppressed'
            )
        if id(response_part) in self.terminations:
            raise CommitException(
                'A terminated response cannot also be suppressed'
            )

        self.informational_suppressions[id(response_part)] = response_part
        return response_part.stream_id

    def stage_pending_request_failures(
            self,
            goaway_part,
            status,
            headers,
            body,
            trailers,
            include_content_length,
    ):
        """Validate one upstream GOAWAY and freeze its pending stream set."""
        if 'flow' not in self.control_before:
            raise CommitException('Pending request failure requires content-reverse from activation')
        if self.settings.side != 'R':
            raise CommitException('Pending requests can be failed only by an upstream GOAWAY')
        if self.pending_failures is not None:
            raise CommitException('Pending requests can be failed only once per callback')
        positions = [index for index, part in enumerate(self.message.parts)
                     if part is goaway_part]
        if len(positions) != 1:
            raise CommitException('GOAWAY anchor must belong to the current message')
        if (not goaway_part.complete or goaway_part.frame_type != 7 or
                goaway_part.stream_id != 0 or len(goaway_part.get_bytes()) < 8):
            raise CommitException('Pending request failure requires a complete GOAWAY')
        position = positions[0]
        if goaway_part.commit() != self.originals[position]:
            raise CommitException('GOAWAY anchor must remain unedited')
        response = self._failure_response(
            status,
            headers,
            body,
            trailers,
            include_content_length,
        )

        flow_state = self.control_before['flow']
        records = flow_state.get('http_streams', {})
        pending = {
            int(stream)
            for stream, record in records.items()
            if record.get('request_headers') and
            not record.get('final_response') and
            not record.get('failure_staged')
        }
        for part in self.message.parts[:position]:
            if not part.complete:
                raise CommitException('GOAWAY selection requires complete preceding frames')
            if part.frame_type == 3:
                pending.discard(part.stream_id)
                continue
            if part.frame_type != 1 or part.headers is None:
                continue
            fields = self._header_fields(part)
            statuses = [value for name, value, _ in fields if name == b':status']
            if statuses and not self.source_informational.get(id(part), False):
                pending.discard(part.stream_id)

        selected = tuple(sorted(pending))
        self.pending_failures = {
            'anchor': goaway_part,
            'streams': selected,
            **response,
        }
        return selected

    def stage_reset_stream_failure(
            self,
            reset_part,
            status,
            headers,
            body,
            trailers,
            include_content_length,
    ):
        """Validate one upstream reset and stage a local stream response."""
        if 'flow' not in self.control_before:
            raise CommitException('Reset stream failure requires content-reverse from activation')
        if self.settings.side != 'R':
            raise CommitException('Only an upstream RST_STREAM can fail a request')
        positions = [index for index, part in enumerate(self.message.parts)
                     if part is reset_part]
        if len(positions) != 1:
            raise CommitException('RST_STREAM anchor must belong to the current message')
        if (not reset_part.complete or reset_part.frame_type != 3 or
                not reset_part.stream_id or len(reset_part.get_bytes()) != 4):
            raise CommitException('Stream failure requires a complete RST_STREAM')
        position = positions[0]
        if reset_part.commit() != self.originals[position]:
            raise CommitException('RST_STREAM anchor must remain unedited')
        if id(reset_part) in self.reset_failures:
            raise CommitException('An RST_STREAM can fail its request only once')
        if any(plan['stream'] == reset_part.stream_id
               for plan in self.reset_failures.values()):
            raise CommitException('A request stream can fail only once per callback')

        record = self.control_before['flow'].get('http_streams', {}).get(
            str(reset_part.stream_id)
        )
        if (record is None or not record.get('request_headers') or
                record.get('final_response') or record.get('failure_staged')):
            raise CommitException('Reset request stream is no longer publishable')

        for part in self.message.parts[:position]:
            if not part.complete:
                raise CommitException('RST_STREAM selection requires complete preceding frames')
            if part.stream_id != reset_part.stream_id:
                continue
            if part.frame_type == 3:
                raise CommitException('A request stream can fail only once per callback')

        response = self._failure_response(
            status,
            headers,
            body,
            trailers,
            include_content_length,
        )
        self.reset_failures[id(reset_part)] = {
            'anchor': reset_part,
            'stream': reset_part.stream_id,
            **response,
        }
        return reset_part.stream_id

    def _failure_response(
            self,
            status,
            headers,
            body,
            trailers,
            include_content_length,
    ):
        """Validate one protocol-owned failure response without staging it."""
        if type(status) is not int or not 400 <= status <= 599:
            raise CommitException('Failure response status must be an integer in 400..599')
        if not isinstance(body, bytes):
            raise CommitException('Failure response body must be bytes')
        if len(body) > 1024 * 1024:
            raise CommitException('Failure response body exceeds 1 MiB')

        length = str(len(body)).encode('ascii')
        regular = self._response_fields(
            headers,
            content_length=length,
            include_content_length=include_content_length,
        )
        trailing = self._response_fields(trailers, trailers=True)
        return {
            'status': status,
            'headers': regular,
            'body': body,
            'trailers': trailing,
        }

    def stage_local_response(self, request, status, headers, body, trailers):
        if 'flow' not in self.control_before:
            raise CommitException('Local responses require content-reverse from activation')
        if self.settings.side != 'L':
            raise CommitException('A local response must be staged while publishing a request')
        if type(status) is not int or not 200 <= status <= 599:
            raise CommitException('Local response status must be an integer in 200..599')
        if not isinstance(body, bytes):
            raise CommitException('Local response body must be bytes')
        if len(body) > 1024 * 1024:
            raise CommitException('Local response body exceeds 1 MiB')

        groups = []
        for group in _h2_content_groups(self.message.parts):
            head = group[0]
            if not head.complete or head.frame_type != 1:
                continue
            fields = self._header_fields(head)
            if any(name == b':method' for name, _, _ in fields):
                groups.append((head, group, fields))

        if request is None:
            if len(groups) != 1:
                raise CommitException('Local response requires exactly one complete request or an explicit request Part')
            selected = groups[0]
        else:
            matches = [group for group in groups if group[0] is request]
            if len(matches) != 1:
                raise CommitException('The selected request Part is not a complete request in this callback')
            selected = matches[0]

        head, group, request_fields = selected
        if id(head) in self.terminations:
            raise CommitException('A terminated request cannot also receive a local response')
        if id(head) in self.informational_responses:
            raise CommitException('An informational response request cannot also receive a local final response')
        if not head.content.complete or any(not part.complete for part in group):
            raise CommitException('Local response requires a complete retained request')
        if id(head) in self.local_responses:
            raise CommitException('A request can have only one local response')

        length = str(len(body)).encode('ascii')
        regular = self._response_fields(headers, content_length=length)
        trailing = self._response_fields(trailers, trailers=True)
        method = next(value for name, value, _ in request_fields if name == b':method')
        self.local_responses[id(head)] = {
            'head': head,
            'parts': tuple(group),
            'stream': head.stream_id,
            'status': status,
            'headers': regular,
            'body': body,
            'trailers': trailing,
            'method': method,
        }

    def stage_termination(self, header, reason, http2_error):
        """Validate and stage a callback-local H2 stream termination."""
        if 'flow' not in self.control_before:
            raise CommitException('H2 termination requires content-reverse from activation')
        if not isinstance(reason, str):
            raise CommitException('H2 termination reason must be text')
        if not 1 <= len(reason.encode('utf-8')) <= 1024:
            raise CommitException('H2 termination reason must be 1..1024 UTF-8 bytes')
        if any(character in reason for character in ('\r', '\n', '\x00')):
            raise CommitException('H2 termination reason contains a control character')
        if type(http2_error) is not int or not 0 <= http2_error <= 0xffffffff:
            raise CommitException('H2 termination error must be an integer in 0..4294967295')
        if not any(part is header for part in self.message.parts):
            raise CommitException('Termination header must belong to the current message')
        if header.frame_type != 1 or not header.complete or header.headers is None:
            raise CommitException('Termination requires complete initial HEADERS')

        fields = self._header_fields(header)
        methods = [value for name, value, _ in fields if name == b':method']
        statuses = [value for name, value, _ in fields if name == b':status']
        if len(methods) + len(statuses) != 1:
            raise CommitException('Termination requires initial request or final response headers')
        if statuses:
            status = statuses[0]
            if not (len(status) == 3 and status.isdigit() and 200 <= int(status) <= 599):
                raise CommitException('Termination requires final response headers, not informational headers')

        groups = [group for group in _h2_content_groups(self.message.parts)
                  if group[0] is header]
        if len(groups) != 1:
            raise CommitException('Termination header does not identify one H2 message')
        if id(header) in self.terminations:
            raise CommitException('An H2 message can be terminated only once')
        if id(header) in self.message_edits:
            raise CommitException('A replaced message cannot also be terminated')
        if id(header) in self.local_responses:
            raise CommitException('A local response request cannot also be terminated')
        if id(header) in self.informational_responses:
            raise CommitException('An informational response request cannot also be terminated')
        if id(header) in self.informational_suppressions:
            raise CommitException('A suppressed informational response cannot also be terminated')

        self.terminations[id(header)] = {
            'head': header,
            'parts': tuple(groups[0]),
            'stream': header.stream_id,
            'kind': 'request' if methods else 'response',
            'reason': reason,
            'http2_error': http2_error,
        }

    def _prepare_terminations(self, flow):
        suppressed = set()
        side = self.settings.side

        for termination in self.terminations.values():
            stream = termination['stream']
            expected_side = 'L' if termination['kind'] == 'request' else 'R'
            if side != expected_side:
                raise CommitException('H2 termination headers arrived from the wrong direction')
            if flow.cancelled(side, stream) or flow.retired(side, stream):
                raise CommitException('H2 termination stream is no longer publishable')
            if flow._contains(flow.state[side].get('opened', {}), stream):
                raise CommitException('H2 termination cannot suppress already published headers')

            suppressed.update(id(part) for part in termination['parts'])
            target = flow.peer if termination['kind'] == 'request' else flow.side
            flow.terminate(stream, target, termination['http2_error'])

        return suppressed

    def _prepare_local_responses(self, flow, cut):
        positions = {id(part): index for index, part in enumerate(self.message.parts)}
        suppressed = set()
        after = {}

        for response in self.local_responses.values():
            stream = response['stream']
            parts = response['parts']
            if flow.cancelled(flow.side, stream) or flow.retired(flow.side, stream):
                raise CommitException('Local response request stream is no longer publishable')
            if any(positions.get(id(part), cut) >= cut for part in parts):
                raise CommitException('Emit the complete retained request with its local response')
            if flow._contains(flow.state[flow.side].get('opened', {}), stream):
                raise CommitException('Local response cannot replace an already published request')
            suppressed.update(id(part) for part in parts)
            after[id(parts[-1])] = response
        return suppressed, after

    @staticmethod
    def _queue_local_response(response, flow, settings, encoder):
        peer = flow.peer
        stream = response['stream']
        trailers = response['trailers']
        body = response['body']
        fields = [(b':status', str(response['status']).encode('ascii'), False)]
        fields.extend(response['headers'])

        flags = 4
        if not body and not trailers:
            flags |= 1
        header = _h2_new_frame(1, flags, stream, b'')
        header.max_frame_size = settings.state[peer]['frame']
        flow.queues[peer].append(header._assemble(encoder.encode(fields)))

        if body:
            flow.queues[peer].append(flow.frame(
                0,
                0 if trailers else 1,
                stream,
                body,
            ))
        if trailers:
            trailer = _h2_new_frame(1, 5, stream, b'')
            trailer.max_frame_size = settings.state[peer]['frame']
            flow.queues[peer].append(trailer._assemble(encoder.encode(trailers)))

        flow.close(flow.side, stream)
        flow.drain(peer)

    @staticmethod
    def _queue_informational_response(response, flow, settings, encoder):
        """Queue one reverse HEADERS block without ending the request stream."""
        peer = flow.peer
        fields = [
            (b':status', str(response['status']).encode('ascii'), False),
            *response['headers'],
        ]
        header = _h2_new_frame(1, 4, response['stream'], b'')
        header.max_frame_size = settings.state[peer]['frame']
        flow.queues[peer].append(header._assemble(encoder.encode(fields)))
        flow.drain(peer)

    def _prepare_informational_responses(self, flow, settings, encoder):
        """Publish staged reverse responses, including for a held request head."""
        for response in self.informational_responses.values():
            stream = response['stream']
            if flow.cancelled(flow.side, stream) or flow.retired(flow.side, stream):
                raise CommitException(
                    'Informational response request stream is no longer publishable'
                )
            record = flow.state.get('http_streams', {}).get(str(stream))
            if record is not None and record.get('final_response'):
                raise CommitException(
                    'Informational response cannot follow a final response'
                )
            self._queue_informational_response(response, flow, settings, encoder)

    def _prepare_informational_suppressions(self, flow, cut):
        """Select only source headers consumed by this Translate prefix."""
        positions = {
            id(part): index for index, part in enumerate(self.message.parts)
        }
        suppressed = set()
        for identity, response_part in self.informational_suppressions.items():
            position = positions.get(identity)
            if position is None or position >= cut:
                raise CommitException(
                    'Emit the informational response anchor when suppressing it'
                )
            if flow.cancelled(flow.side, response_part.stream_id):
                continue
            suppressed.add(identity)
        return suppressed

    @staticmethod
    def _queue_failure_response(response, stream, flow, settings, encoder):
        """Queue one same-direction response through the existing H2 scheduler."""
        side = flow.side
        trailers = response['trailers']
        body = response['body']
        fields = [(b':status', str(response['status']).encode('ascii'), False)]
        fields.extend(response['headers'])

        flags = 4
        if not body and not trailers:
            flags |= 1
        header = _h2_new_frame(1, flags, stream, b'')
        header.max_frame_size = settings.state[side]['frame']
        flow.queues[side].append(header._assemble(encoder.encode(fields)))
        if body:
            flow.queues[side].append(flow.frame(
                0,
                0 if trailers else 1,
                stream,
                body,
            ))
        if trailers:
            trailer = _h2_new_frame(1, 5, stream, b'')
            trailer.max_frame_size = settings.state[side]['frame']
            flow.queues[side].append(trailer._assemble(encoder.encode(trailers)))
        flow.drain(side)

    def _prepare_pending_failures(self, flow, cut, settings, encoder):
        plan = self.pending_failures
        if plan is None:
            return set()
        positions = [index for index, part in enumerate(self.message.parts)
                     if part is plan['anchor']]
        if len(positions) != 1 or positions[0] >= cut:
            raise CommitException('Emit the GOAWAY anchor with its pending request failures')

        flow.consume_failed_goaway(plan['anchor'])
        for stream in plan['streams']:
            flow.fail_stream(stream)
            self._queue_failure_response(plan, stream, flow, settings, encoder)
        return {id(plan['anchor'])}

    def _prepare_reset_failures(self, flow, cut, settings, encoder):
        """Consume selected resets and queue their stream-local responses."""
        anchors = set()
        positions = {id(part): index for index, part in enumerate(self.message.parts)}
        plans = sorted(
            self.reset_failures.values(),
            key=lambda plan: positions.get(id(plan['anchor']), cut),
        )
        for plan in plans:
            position = positions.get(id(plan['anchor']))
            if position is None or position >= cut:
                raise CommitException('Emit the RST_STREAM anchor with its failure response')
            flow.fail_stream(plan['stream'])
            self._queue_failure_response(plan, plan['stream'], flow, settings, encoder)
            anchors.add(id(plan['anchor']))
        return anchors

    @staticmethod
    def _discard_held(parts, flow, side):
        kept = []
        direction = flow.state[side]
        for part in parts:
            if part.stream_id and (
                    flow.cancelled(side, part.stream_id) or flow.failed(part.stream_id)):
                if part.frame_type == 0 and len(part._wire) >= 9:
                    amount = int.from_bytes(bytes(part._wire)[:3], 'big')
                    flow.discard_input(side, part.stream_id, amount)
                    if not part.complete:
                        direction['discard_bytes'] = 9 + amount - len(part._wire)
                    continue
                if part.frame_type in (1, 5):
                    # Keep the source HPACK block until its direction resumes.
                    # It will update only the input decoder, never the peer.
                    part.headers = None
                    part._pending = None
                    part._translate_draft = False
                    part._translate_cancelled = True
                    for name in ('_body_plain', '_decoded_body'):
                        if hasattr(part, name):
                            delattr(part, name)
            kept.append(part)
        flow.disposed.add(side)
        return kept

    def _validate_push(self, part):
        """Check push envelope, without pretending to track every stream state."""
        promised = int.from_bytes(part._prefix[-4:], 'big') & 0x7fffffff

        if self.settings.side != 'R' or not self.settings.limits.get('push', 1):
            raise CommitException('PUSH_PROMISE requires server direction and enabled push')

        if not part.stream_id or not part.stream_id & 1 or not promised or promised & 1:
            raise CommitException('PUSH_PROMISE requires a client stream and an even nonzero promised stream')

    def _decode_headers(self, part, active):
        """Resolve source indices without changing the receiver's table."""
        fields = _translate_decode(self.decoder, part.get_bytes())
        headers = H2Headers([
            HpackField(field[0], field[1], 'never' if not field.indexable else 'without', 0, 0)
            for field in fields
        ])
        self.decoded[id(part)] = headers
        self.source_informational[id(part)] = _translate_informational(
            part, [(field.name, field.value, False) for field in headers.entries])
        self.source_lengths[id(part)] = tuple(field.value for field in headers.entries
                                             if field.name == b'content-length')

        if active and not getattr(part, '_translate_draft', False):
            part.headers = headers
            return

        if active:
            return  # Logical edits in a complete held part survive the next run.

        # Before opt-in, preserve the ordinary rewrite view. Remember how its
        # fields map to decoded values if the script later chooses translate.
        if part.headers is not None:
            values = iter(headers.entries)

            for field in part.headers.entries:
                resolved = None if field.indexing == 'table-size' else next(values)

                if resolved is not None:
                    # Enrich the facade, retaining original HPACK instructions.
                    # An unchanged rewrite must still emit its exact raw bytes.
                    field.name, field.value = resolved.name, resolved.value
                    field._initial = field._state()

                self.original_fields[id(field)] = (field._state(), resolved)

    def _resolve_field(self, field):
        """Turn an activation-time rewrite field into a logical header."""
        previous = self.original_fields.get(id(field))

        if previous is None:
            return field

        state, resolved = previous
        current = field._state()

        if current == state:
            # None means a source table-size update, already handled by decoder.
            return resolved

        if current[2:] == state[2:]:
            indexing = 'never' if state[2] == 'never' else 'without'
            return HpackField(field.name, field.value, indexing, 0, 0)

        return field

    def _header_fields(self, part):
        if part._pending is not None:
            raise CommitException('Translate requires logical headers, not raw HPACK')

        headers = part.headers

        if headers is None or headers._encode() == part._data:
            headers = self.decoded[id(part)]

        fields = []

        for field in headers.entries:
            field = self._resolve_field(field)

            if field is None:
                continue

            logical_value = isinstance(field.name, bytes) and isinstance(field.value, bytes)
            explicit_index = field.index or field.name_index
            supported_indexing = field.indexing in ('without', 'incremental', 'never')

            if not logical_value or explicit_index or not supported_indexing:
                raise CommitException('Explicit HPACK indices are rewrite-only')

            fields.append((field.name, field.value, field.indexing == 'never'))

        return fields

    def translate(self):
        import copy
        import json

        message = self.message

        if self.result is not None:
            raise CommitException('Call translate exactly once per callback')
        if tuple(id(p) for p in message.parts) != self.identities:
            raise CommitException('Translate cannot insert, remove or reorder Parts yet')

        boundary = message.parts._held_from
        cut = len(message.parts)

        if boundary is not None:
            positions = [i for i, p in enumerate(message.parts) if p is boundary]

            if len(positions) != 1:
                raise CommitException('Hold boundary was removed or duplicated')

            cut = positions[0]

        output = bytearray()
        # A failed assembly can be retried. Publish neither bytes nor table
        # changes until the entire message and checkpoint have passed validation.
        encoder = copy.deepcopy(self.encoder)
        peer_encoder = copy.deepcopy(self.peer_encoder)
        settings = _TranslationSettings(self.control_before, self.settings.side)
        flow = (_TranslationFlow(settings.state['flow'], settings.side)
                if 'flow' in settings.state else None)
        incoming = _TranslationInput(flow) if flow is not None else None
        if incoming is not None:
            direction = flow.state[settings.side]
            if 'discard_bytes' in direction:
                remaining = max(0, direction['discard_bytes'] - len(message.bytes))
                if remaining:
                    direction['discard_bytes'] = remaining
                else:
                    del direction['discard_bytes']
            incoming.receive(settings.side, message.bytes)
        if flow is not None:
            self._prepare_informational_responses(
                flow,
                settings,
                peer_encoder,
            )
        failure_anchors = set()
        if flow is not None:
            # Stream failures are staged in source order before a later
            # connection failure. This preserves observable response ordering
            # for RST_STREAM immediately followed by GOAWAY.
            failure_anchors.update(
                self._prepare_reset_failures(flow, cut, settings, encoder)
            )
            failure_anchors.update(
                self._prepare_pending_failures(flow, cut, settings, encoder)
            )
        terminal = set()
        if flow is not None:
            # Translate owns terminal control even when an application body is
            # held. Otherwise a same-direction reset could wait behind that body.
            for part, original in zip(message.parts, self.originals):
                if part.complete and part.frame_type in (3, 7):
                    if part.commit() != original:
                        raise CommitException('Translate terminal controls cannot be edited')
                    if id(part) in failure_anchors:
                        pass
                    elif part.frame_type == 3 and flow.failed(part.stream_id):
                        # The GOAWAY failure response already owns this stream.
                        # A later reset from the failed upstream connection
                        # must not cancel or truncate that local response.
                        pass
                    elif (part.frame_type == 7 and settings.side == 'R' and
                          flow.state.get('failed_goaway') is not None):
                        flow.consume_failed_goaway(part)
                    else:
                        flow.accept(part, original)
                    terminal.add(id(part))
        termination_suppressed = self._prepare_terminations(flow) if flow is not None else set()
        hold_credit = _TranslationHoldCredit(self, flow, incoming, cut) if flow is not None else None

        emitted = message.parts[:cut]
        live = [part for part in emitted if flow is None or not flow.cancelled(settings.side, part.stream_id)]
        edits = _TranslationMessageEdits(self, flow, cut)
        local_suppressed, local_after = self._prepare_local_responses(flow, cut) if flow is not None else (set(), {})
        informational_suppressed = (
            self._prepare_informational_suppressions(flow, cut)
            if flow is not None else set()
        )
        body_overrides = _encoded_h2_bodies(live)
        body_overrides.update(edits.body_overrides)
        header_lengths = self._body_lengths(live, body_overrides, flow)
        header_lengths.update(edits.lengths)

        for part, original in zip(emitted, self.originals):
            start = len(output)
            if id(part) in terminal:
                continue
            if not part.complete:
                raise CommitException('Incomplete H2 part: hold_from(part) before translate')

            if (flow is not None and part.stream_id and
                    flow.failed(part.stream_id)):
                # Source HPACK was already decoded during transaction setup.
                # Failed stream bytes update only native input accounting.
                flow.accept(part, b'')
                continue

            if id(part) in termination_suppressed:
                flow.accept(part, b'')
                continue

            if flow is not None and flow.cancelled(settings.side, part.stream_id) and part.frame_type in (1, 5):
                continue  # Input HPACK was decoded; cancelled drafts have no output context.

            if id(part) in local_suppressed:
                flow.accept(part, b'')
                response = local_after.get(id(part))
                if response is not None:
                    self._queue_local_response(response, flow, settings, peer_encoder)
                continue

            if id(part) in informational_suppressed:
                # Input HPACK was decoded during transaction setup. Accepting
                # an empty publication settles source accounting without
                # advancing the downstream encoder or exposing this block.
                flow.accept(part, b'')
                continue

            if id(part) in edits.suppressed:
                # Decode source trailers as usual, but do not publish them into
                # the output HPACK table. Source completion is still observed.
                flow.accept(part, b'')
                continue

            if part._initial[0] == 0:
                output.extend(self._translate_data(body_overrides.get(id(part), part), original,
                                                   resizing=flow is not None))
                if id(part) in edits.flags:
                    output[start + 4] = (output[start + 4] & ~1) | (edits.flags[id(part)] & 1)
            elif part._initial[0] not in (1, 5):
                if part.commit() != original:
                    raise CommitException('Translate supports logical header and DATA edits only')

                if part.frame_type == 4:
                    _translate_encoder_settings(encoder, settings.process(part))
                    output.extend(settings.forward_wire)
                else:
                    output.extend(original)

            else:
                if (part.frame_type, part.flags, part.stream_id) != part._initial:
                    raise CommitException('Translate headers must preserve frame type, flags and stream id')

                fields = edits.headers.get(id(part))
                if fields is None:
                    fields = self._header_fields(part)
                if id(part) in header_lengths:
                    fields = [(name, header_lengths[id(part)] if name == b'content-length' else value, sensitive)
                              for name, value, sensitive in fields]
                if (flow is not None and part.frame_type == 1 and
                        not flow.cancelled(settings.side, part.stream_id) and
                        not flow.retired(settings.side, part.stream_id)):
                    if any(name in (b':method', b':status') for name, _, _ in fields):
                        previous = flow.state[settings.side]['streams'].get(str(part.stream_id))
                        only_informational = self.informational(part)
                        if previous is not None:
                            only_informational = only_informational and previous.get('informational_only', False)
                        entry = flow.stream(settings.side, part.stream_id)
                        entry['informational_only'] = only_informational
                        entry['content_length'] = any(
                            name == b'content-length' for name, _, _ in fields)
                draft = copy.copy(part)
                draft.max_frame_size = min(part.max_frame_size, settings.limits['frame'])
                draft.flags = edits.flags.get(id(part), part.flags)
                output.extend(draft._assemble(encoder.encode(fields)))

            if flow is not None:
                wire = bytes(output[start:])
                del output[start:]
                flow.accept(part, wire)
                if wire and part.frame_type == 1:
                    methods = [value for name, value, _ in fields
                               if name == b':method']
                    statuses = [value for name, value, _ in fields
                                if name == b':status']
                    if settings.side == 'L' and len(methods) == 1:
                        flow.observe_request(part.stream_id, bool(part.flags & 1))
                    elif (settings.side == 'R' and len(statuses) == 1 and
                          not self.informational(part)):
                        flow.observe_final_response(part.stream_id)
                edits.emit_after(part, encoder, settings, flow)

            if len(output) > 1024 * 1024:
                raise CommitException('Translated output exceeds 1 MiB')

        # Appending after the emitted prefix cannot split HEADERS/CONTINUATION.
        # Do not emit around a held boundary: the user explicitly retained it.
        if boundary is None:
            output.extend(settings.pending_policy_frame())

        reverse_output = b''
        suffix = [part for part in message.parts[cut:] if id(part) not in terminal]
        suffix_fields = {}
        peer_held = self.peer_hold
        if flow is not None:
            # Work on private copies: failed serialization may be retried using
            # the same callback-local draft and neither hold may change early.
            copied, _ = _restore(_checkpoint([copy.copy(part) for part in suffix], {}))
            suffix_fields = {id(clone): self._header_fields(original)
                             for original, clone in zip(suffix, copied)
                             if original.complete and original.frame_type in (1, 5)}
            suffix = self._discard_held(copied, flow, settings.side)
            if self.peer_hold_known:
                peer_parts, peer_sizes = _restore(self.peer_hold) if self.peer_hold else ([], {})
                peer_parts = self._discard_held(peer_parts, flow, flow.peer)
                peer_held = _checkpoint(peer_parts, peer_sizes) if peer_parts else None
            flow.output[settings.side].extend(output)
            forward, reverse_output = flow.finish()
            incoming.finish()
            hold_credit.advance()
            if flow.state.get('hold_reserved') and all(
                    not flow.bodies(side) and
                    not flow.state[side].get('advance_due', 0) and
                    not flow.state[side]['input']['owned'] for side in ('L', 'R')):
                # No reserved stream or source bytes remain to back future
                # grants/output. Remaining HPACK metadata is charged as actual
                # state; a later reservation must pass admission again.
                flow.state['hold_reserved'] = False
            if sum(map(len, flow.output.values())) > 1024 * 1024:
                raise CommitException('Translated directional output exceeds 1 MiB')
            forward, reverse_output = bytes(flow.output[flow.side]), bytes(flow.output[flow.peer])
            output = bytearray(forward)

        if len(output) > 1024 * 1024:
            raise CommitException('Translated output exceeds 1 MiB')

        decoder = self.decoder

        if cut < len(message.parts):
            # Views decoded the full input speculatively. Publish only the table
            # after the emitted prefix, so retained blocks are consumed once.
            decoder = _translate_hpack.Decoder()
            _translate_table_load(decoder, self.input_before)
            replay_settings = _TranslationSettings(self.control_before, self.settings.side)

            for part in emitted:
                if part.frame_type == 4:
                    _translate_decoder_settings(decoder, replay_settings.process(part))

                if part.frame_type in (1, 5):
                    _translate_decode(decoder, part._data)

        checkpoint = {
            'version': 1,
            'input': _translate_table_dump(decoder),
            'output': _translate_table_dump(encoder),
        }

        if len(json.dumps(checkpoint)) > 65536:
            raise CommitException('Translate checkpoint exceeds 64 KiB')

        peer_checkpoint = self.peer_checkpoint_before
        if self.local_responses or self.informational_responses:
            if peer_checkpoint is None:
                peer_decoder = _translate_hpack.Decoder()
                peer_input = _translate_table_dump(peer_decoder)
            else:
                peer_input = copy.deepcopy(peer_checkpoint['input'])
            peer_checkpoint = {
                'version': 1,
                'input': peer_input,
                'output': _translate_table_dump(peer_encoder),
            }
            if len(json.dumps(peer_checkpoint)) > 65536:
                raise CommitException('Peer translate checkpoint exceeds 64 KiB')

        if len(json.dumps(settings.state)) > 1024 * 1024:
            raise CommitException('Translate control checkpoint exceeds 1 MiB')

        result = bytes(output)

        if boundary is not None:
            saved = []

            try:
                for part in suffix:
                    if not part.complete and (part._pending is not None or
                            (part.frame_type, part.flags, part.stream_id) != part._initial):
                        raise CommitException('Cannot hold an edited incomplete H2 part')

                    if part.complete and part.frame_type in (1, 5) and not (
                            flow is not None and flow.cancelled(settings.side, part.stream_id)):
                        # Normalize only the checkpoint, never the user's live draft.
                        # Copies retain resolved logical fields from the live draft.
                        fields = suffix_fields[id(part)] if flow is not None else self._header_fields(part)
                        saved.append((part, part.headers, getattr(part, '_translate_draft', None)))
                        part.headers = H2Headers([
                            HpackField(name, value, 'never' if sensitive else 'without', 0, 0)
                            for name, value, sensitive in fields
                        ])
                        part._translate_draft = True

                held = _checkpoint(suffix, message._body_sizes)
            finally:
                for part, headers, marker in saved:
                    part.headers = headers

                    if marker is None:
                        del part._translate_draft
                    else:
                        part._translate_draft = marker

            if len(json.dumps(held)) + (len(output) + 2) // 3 * 4 > 1400 * 1024:
                raise CommitException('Translate prefix and hold exceed worker response budget')

            result = HeldCommit(result, held, len(suffix))

        if flow is not None and flow.state.get('hold_reserved'):
            for side, hold in ((flow.side, result.checkpoint if isinstance(result, HeldCommit) else None),
                               (flow.peer, peer_held)):
                capacity = flow.state[side].get('hold_capacity', 1024 * 1024)
                if hold is not None and len(json.dumps(hold)) > capacity:
                    raise CommitException('Reserved hold checkpoint exceeds admitted capacity')

        self.result = result
        self.checkpoint = checkpoint
        self.peer_checkpoint = peer_checkpoint
        self.peer_checkpoint_changed = bool(
            self.local_responses or self.informational_responses
        )
        self.control_checkpoint = settings.state
        self.reverse_output = reverse_output
        self.peer_hold_result = peer_held
        self.peer_hold_changed = self.peer_hold_known and peer_held != self.peer_hold
        if flow is not None:
            self.flow_summary = {
                'pending_bytes': sum(len(wire) for queue in flow.queues.values() for wire in queue),
                'forward_bytes': len(output), 'reverse_bytes': len(reverse_output),
            }
        return self.result

    def _body_lengths(self, parts, overrides, flow):
        """Repair retained headers; never pretend to repair headers already sent."""
        def size(part):
            draft = overrides.get(id(part), part)
            return len(draft._data if draft._pending is None else draft._pending)

        changed = {part.stream_id for part in parts if part.frame_type == 0 and
                   size(part) != len(part._data)}
        lengths = {}
        local = set()

        for group in _h2_content_groups(parts):
            head = group[0]
            if not any(part.frame_type == 0 and size(part) != len(part._data) for part in group):
                continue
            local.add(head.stream_id)
            fields = self._header_fields(head)
            if not any(name == b'content-length' for name, _, _ in fields):
                continue
            if not head.content.complete:
                raise CommitException('Retain complete content before resizing a Content-Length body')
            length = sum(size(part) for part in group if part.frame_type == 0)
            lengths[id(head)] = str(length).encode()

        if flow is not None:
            for stream in changed - local:
                if flow.cancelled(flow.side, stream):
                    continue
                if flow.stream(flow.side, stream)['content_length']:
                    raise CommitException('Cannot resize body after emitting Content-Length; hold the header first')

        return lengths

    @staticmethod
    def _translate_data(part, original, *, resizing=False):
        """Keep original DATA geometry unless a negotiated resize needs reframing.

        The flow ledger, not this serializer, splits by current output credit.
        Legacy peers retain exact frame headers, padding and DATA length.
        """
        if (part.frame_type, part.flags, part.stream_id) != part._initial:
            raise CommitException('Translate DATA must preserve frame type, flags and stream id')

        if part._pending is None:
            return original  # Untouched DATA does not need materialization.

        data = _h2_bytes(part.get_bytes())

        if len(data) != len(part._data):
            if not resizing:
                raise CommitException('Translate DATA resizing requires content-reverse capability from connection start')
            return _TranslationFlow.frame(0, part.flags & ~8, part.stream_id, data)

        start = 9 + len(part._prefix)
        end = start + len(data)
        return original[:start] + data + original[end:]


def _prepare_translation(message, request):
    active = request.get('translate_active', False)

    if not active and not request.get('translate_allowed', False):
        return

    try:
        control = request.get('translate_control')
        side = request.get('event', {}).get('details', {}).get('info', {}).get('side', 'L')
        settings = _TranslationSettings(control, side)
        h2_observed = (
            (message.bytes and _H2_PREFACE.startswith(
                message.bytes[:len(_H2_PREFACE)]))
            or any(p.is_a(PartType.Http2.Part) for p in message.parts)
        )

        if not active and not h2_observed:
            return

        if active:
            _resume_translation(message, request.get('held_parts'), settings)
        else:
            _resume_translation(message, None, settings)
        info = request.get('event', {}).get('details', {}).get('info', {})
        reverse_capable = info.get('webhook_control', {}).get('content-reverse') is True
        transaction = _Translation(
            message,
            request.get('translate_state'),
            request.get('peer_translate_state'),
            active,
            control,
            side,
            reverse_capable,
        )
        transaction.hold_credit_available = request.get('hold_credit_available') is True
        transaction.peer_hold_known = 'peer_held_parts' in request
        transaction.peer_hold = request.get('peer_held_parts')
        if transaction.control_before.get('flow', {}).get('hold_reserved') and not request.get('hold_credit_reserved'):
            raise CommitException('Body reservation owner lost; reconnect')
        object.__setattr__(message, '_translation', transaction)
    except Exception as error:
        if active:
            raise CommitException(str(error)) from error

        # A normal rewrite callback must not fail just because it could have
        # chosen translate. Surface this error only if it actually chooses it.
        object.__setattr__(message, '_translation_error', str(error))

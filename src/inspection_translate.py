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
        reservation = self.flow.state[side].get('body')
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
    INPUT_CAPACITY = MAX_BODY + 65535

    def __init__(self, transaction, flow, incoming, cut):
        self.flow, self.incoming = flow, incoming
        side = flow.side
        direction = flow.state[side]
        for part, limit in transaction.body_reservations:
            if not transaction.hold_credit_available:
                raise CommitException('Body reservation requires backend admission support')
            positions = [i for i, item in enumerate(transaction.message.parts) if item is part]
            if not positions or positions[0] < cut or not part.complete or part.frame_type != 1:
                raise CommitException('Reserve a complete initial HEADERS part in the held suffix')
            fields = transaction._header_fields(part)
            if not any(name in (b':method', b':status') for name, _, _ in fields):
                raise CommitException('Body reservation requires initial request or response headers')
            lengths = transaction.source_lengths[id(part)]
            if any(not value.isdigit() or int(value) > limit for value in lengths):
                raise CommitException('Content-Length exceeds reserved encoded body limit')
            current = direction.get('body')
            if current and (current['stream'] != part.stream_id or current['limit'] != limit):
                raise CommitException('Only one body reservation per direction; its limit is immutable')
            if not current:
                if str(part.stream_id) in direction['streams'] or flow.retired(side, part.stream_id):
                    raise CommitException('Body reservation requires headers retained before any output')
                direction['body'] = {'stream': part.stream_id, 'limit': limit,
                                     'stream_due': 0, 'advanced': 0}
                flow.state['hold_reserved'] = True
        if flow.state.get('hold_reserved') and not transaction.hold_credit_available:
            raise CommitException('Body reservation backend capability lost')
        # A reserved body is an all-or-nothing retained semantic message.
        reservation = direction.get('body')
        if reservation:
            for part in transaction.message.parts[:cut]:
                if part.frame_type == 1 and part.stream_id == reservation['stream']:
                    if not part.content.complete:
                        raise CommitException('Reserved body must remain held until complete')

    def advance(self):
        for side in ('L', 'R'):
            direction = self.flow.state[side]
            reservation = direction.get('body')
            if not reservation:
                continue
            stream = reservation['stream']
            if self.incoming.cancelled(side, stream):
                # Only a fully accepted original body has no retained Parts to
                # dispose of in another callback direction. Output cancellation
                # has already discarded its DATA and settled ownership in finish().
                if reservation.get('released') and not reservation['stream_due']:
                    if self.flow.cancelled(side, stream):
                        del direction['body']
                    # A retained reset affects input policing before forwarding.
                    # Keep the reservation until that reset is actually accepted.
                    continue
                raise CommitException('Reserved H2 body cancelled; strict teardown releases reservation')
            if self.flow.retired(side, stream):
                if reservation['stream_due']:
                    raise CommitException('Reserved H2 body credit did not settle')
                del direction['body']
                continue
            state = self.incoming.direction(side)
            entry = state['streams'][str(stream)]
            received, limit = entry['received'], reservation['limit']
            if received > limit or (received == limit and not entry['ended']):
                raise CommitException('Reserved H2 body limit exhausted before completion')
            if entry['ended']:
                continue
            owned_output = sum(item.get('owned', 0) for item in direction['streams'].values())
            held = state['owned'] - owned_output
            room = self.INPUT_CAPACITY - state['owned'] - state['window']
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
        self.queues = {key: [base64.b64decode(value, validate=True)
                             for value in state[key]['queue']] for key in ('L', 'R')}

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

    def accept(self, part, wire):
        side = self.side
        kind = part._initial[0]

        if kind == 8:
            self.update(part)
            return
        if kind == 4:
            self.settings(part)
        if kind == 3:
            self.reset(part)
        if kind == 7:
            self.goaway(part)

        if kind == 0:
            amount = int.from_bytes(bytes(part._wire)[:3], 'big')
            direction = self.state[side]
            # Early connection credit belongs to the retained input prefix,
            # which is released in source order. Stream credit has its own debt.
            advanced = min(amount, direction.get('advance_due', 0))
            direction['advance_due'] = direction.get('advance_due', 0) - advanced
            direction['credit'] += amount - advanced
            if self.cancelled(side, part.stream_id):
                # In-flight DATA after reset still consumes connection credit.
                direction['cancelled_owned'] = direction.get('cancelled_owned', 0) + amount
                return
            stream = self.stream(side, part.stream_id)
            if stream['closed'] or stream.get('ended'):
                raise CommitException('DATA after translated stream termination')
            stream['ended'] = bool(part.flags & 1)
            # Include padding and its length byte, but not the frame header.
            stream['owned'] = stream.get('owned', 0) + amount
            reservation = direction.get('body')
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

        if kind == 1 and part.flags & 1 and not self.cancelled(side, part.stream_id):
            if not self.retired(side, part.stream_id):
                self.stream(side, part.stream_id)['ended'] = True

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
            wire = queue[0]
            if wire.startswith(_H2_PREFACE) or wire[3] != 0:
                self.output[side].extend(queue.pop(0))
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
                self.output[side].extend(queue.pop(0))
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
                queue[0] = self.frame(0, flags, stream_id, payload)
                continue

            if available <= 0:
                break

            self.output[side].extend(self.frame(0, flags & ~1, stream_id, payload[:available]))
            queue[0] = self.frame(0, flags, stream_id, payload[available:])
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

    @api_method('header: RewritePart, max_bytes: int', 'None',
                'Reserve bounded input capacity for a retained H2 body and advance credit only during explicit Translate. Keep the initial header held until the complete body is available. The limit counts original encoded DATA including padding, up to 256 KiB; it is immutable. One collecting body per direction. Backend checkpoint capacity remains reserved until connection end.',
                'api.connection.set_mode(Mode.Translate)\nfor part in api.message.parts:\n    if part.type == PartType.Http2.Header and part.complete and part.content.complete is False:\n        api.message.parts.hold_from(part)\n        api.connection.http2.reserve_body(part, 128 * 1024)\n        break\nreturn api.message.translate()',
                availability='Live sole flow deployment with backend reservation support and content-reverse. Cancellation while original body Parts remain held, or exhausted capacity, tears down strict translation. Fully released bodies may cancel pending output without closing the connection.',
                access='staged body reservation')
    def reserve_body(self, header, max_bytes):
        if type(max_bytes) is not int or not 0 < max_bytes <= _TranslationHoldCredit.MAX_BODY:
            raise CommitException('Body reservation limit must be an integer in 1..262144')
        transaction = self._connection._transaction()
        if 'flow' not in transaction.control_before:
            raise CommitException('Body reservation requires content-reverse from activation')
        transaction.body_reservations = [(part, limit) for part, limit in transaction.body_reservations
                                         if part is not header] + [(header, max_bytes)]

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


class _Translation:
    def __init__(self, message, checkpoint, active, control=None, side='L', reverse_capable=False):
        if _translate_hpack is None:
            raise CommitException('H2 translate requires python-hpack')

        self.message = message
        self.decoder = _translate_hpack.Decoder()
        self.encoder = _translate_hpack.Encoder()
        self.result = None
        self.checkpoint = None
        self.control_checkpoint = None
        self.reverse_output = b''
        self.flow_summary = None
        self.body_reservations = []
        self.hold_credit_available = False
        self.control_before = _TranslationSettings(control, side).state
        if control is None and reverse_capable:
            self.control_before['flow'] = _TranslationFlow.initial()
        if 'flow' in self.control_before and not reverse_capable:
            raise CommitException('Translate lost content-reverse capability')
        self.settings = _TranslationSettings(control, side)
        self.decoded = {}
        self.source_lengths = {}
        self.original_fields = {}
        self.originals = tuple(bytes(p._wire) for p in message.parts)
        self.identities = tuple(id(p) for p in message.parts)

        if checkpoint is not None:
            if checkpoint.get('version') != 1:
                raise CommitException('Unsupported translate checkpoint')

            _translate_table_load(self.decoder, checkpoint['input'])
            _translate_table_load(self.encoder, checkpoint['output'])

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

        object.__setattr__(message, '_body_sizes', {
            id(group[0]): sum(len(p._data) for p in group if p.frame_type == 0)
            for group in _h2_content_groups(message.parts)
        })

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
        settings = _TranslationSettings(self.control_before, self.settings.side)
        flow = (_TranslationFlow(settings.state['flow'], settings.side)
                if 'flow' in settings.state else None)
        incoming = _TranslationInput(flow) if flow is not None else None
        if incoming is not None:
            incoming.receive(settings.side, message.bytes)
        hold_credit = _TranslationHoldCredit(self, flow, incoming, cut) if flow is not None else None

        emitted = message.parts[:cut]
        body_overrides = _encoded_h2_bodies(emitted)
        header_lengths = self._body_lengths(emitted, body_overrides, flow)

        for part, original in zip(emitted, self.originals):
            start = len(output)
            if not part.complete:
                raise CommitException('Incomplete H2 part: hold_from(part) before translate')

            if part._initial[0] == 0:
                output.extend(self._translate_data(body_overrides.get(id(part), part), original,
                                                   resizing=flow is not None))
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

                fields = self._header_fields(part)
                if id(part) in header_lengths:
                    fields = [(name, header_lengths[id(part)] if name == b'content-length' else value, sensitive)
                              for name, value, sensitive in fields]
                if (flow is not None and part.frame_type == 1 and
                        not flow.cancelled(settings.side, part.stream_id) and
                        not flow.retired(settings.side, part.stream_id)):
                    if any(name in (b':method', b':status') for name, _, _ in fields):
                        flow.stream(settings.side, part.stream_id)['content_length'] = any(
                            name == b'content-length' for name, _, _ in fields)
                previous_size = part.max_frame_size

                try:
                    part.max_frame_size = min(previous_size, settings.limits['frame'])
                    output.extend(part._assemble(encoder.encode(fields)))
                finally:
                    part.max_frame_size = previous_size

            if flow is not None:
                wire = bytes(output[start:])
                del output[start:]
                flow.accept(part, wire)

            if len(output) > 1024 * 1024:
                raise CommitException('Translated output exceeds 1 MiB')

        # Appending after the emitted prefix cannot split HEADERS/CONTINUATION.
        # Do not emit around a held boundary: the user explicitly retained it.
        if boundary is None:
            output.extend(settings.pending_policy_frame())

        reverse_output = b''
        if flow is not None:
            flow.output[settings.side].extend(output)
            forward, reverse_output = flow.finish()
            incoming.finish()
            hold_credit.advance()
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

        if len(json.dumps(settings.state)) > 1024 * 1024:
            raise CommitException('Translate control checkpoint exceeds 1 MiB')

        result = bytes(output)

        if boundary is not None:
            suffix = message.parts[cut:]
            saved = []

            try:
                for part in suffix:
                    if not part.complete and (part._pending is not None or
                            (part.frame_type, part.flags, part.stream_id) != part._initial):
                        raise CommitException('Cannot hold an edited incomplete H2 part')

                    if part.complete and part.frame_type in (1, 5):
                        # Normalize only the checkpoint, never the user's live draft.
                        fields = self._header_fields(part)
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

        self.result = result
        self.checkpoint = checkpoint
        self.control_checkpoint = settings.state
        self.reverse_output = reverse_output
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

        if active:
            _resume_translation(message, request.get('held_parts'), settings)
        elif ((message.bytes and _H2_PREFACE.startswith(message.bytes[:len(_H2_PREFACE)])) or
              any(p.is_a(PartType.Http2.Part) for p in message.parts)):
            _resume_translation(message, None, settings)
        info = request.get('event', {}).get('details', {}).get('info', {})
        reverse_capable = info.get('webhook_control', {}).get('content-reverse') is True
        transaction = _Translation(message, request.get('translate_state'), active, control, side, reverse_capable)
        transaction.hold_credit_available = request.get('hold_credit_available') is True
        if transaction.control_before.get('flow', {}).get('hold_reserved') and not request.get('hold_credit_reserved'):
            raise CommitException('Body reservation owner lost; reconnect')
        object.__setattr__(message, '_translation', transaction)
    except Exception as error:
        if active:
            raise CommitException(str(error)) from error

        # A normal rewrite callback must not fail just because it could have
        # chosen translate. Surface this error only if it actually chooses it.
        object.__setattr__(message, '_translation_error', str(error))

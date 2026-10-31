"""Public WebSocket value observations; no frames, sockets or proxy internals."""

from copy import deepcopy


def normalize(value):
    if isinstance(value, bytes):
        return {'bytes': value.hex()}
    if isinstance(value, (tuple, list)):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {name: normalize(item) for name, item in value.items()}
    if hasattr(value, 'get_state'):
        return {'object': type(value).__name__, 'state': normalize(value.get_state())}
    return value


def collect(websocket):
    results = {}
    for opcode in (0, 1, 2, 8, 9, 10, 3):
        for content in (b'hello', b'\xff', b''):
            label = str(opcode) + '/' + content.hex()
            observations = []
            try:
                message = websocket.WebSocketMessage(opcode, True, content, timestamp=123)
            except Exception as error:
                results[label] = {'error': type(error).__name__, 'message': str(error)}
                continue
            observations.append({'state': normalize(message.get_state()),
                                 'is_text': message.is_text, 'repr': repr(message),
                                 'opcode_name': message.type.name})
            for operation in ('read_text', 'write_text', 'drop', 'restore', 'copy'):
                try:
                    value = None
                    if operation == 'read_text':
                        value = message.text
                    elif operation == 'write_text':
                        message.text = 'changed \u2603'
                    elif operation == 'drop':
                        value = message.drop()
                    elif operation == 'restore':
                        message.set_state((2, False, b'restored', 456, False, True))
                    else:
                        copied = message.copy()
                        value = {'state': normalize(copied.get_state()),
                                 'distinct': copied is not message}
                    observations.append({'operation': operation, 'value': value,
                                         'state': normalize(message.get_state())})
                except Exception as error:
                    observations.append({'operation': operation, 'error': type(error).__name__,
                                         'message': str(error)})
            results[label] = observations

    message = websocket.WebSocketMessage(1, False, b'saved', timestamp=123)
    data = websocket.WebSocketData([message], True, 1000, 'finished', 456)
    state = data.get_state()
    original = deepcopy(state)
    restored = websocket.WebSocketData.from_state(state)
    copied = data.copy()
    copied.messages[0].content = b'copy only'
    results['data'] = {
        'state': normalize(original),
        'restored': normalize(restored.get_state()),
        'input_after_restore': normalize(state),
        'copy': normalize(copied.get_state()),
        'original_after_copy_edit': normalize(data.get_state()),
        'default': normalize(websocket.WebSocketData().get_state()),
    }
    for operation in ('set', 'from'):
        for variant in ('valid', 'missing', 'extra'):
            data = websocket.WebSocketData([
                websocket.WebSocketMessage(1, True, b'old', timestamp=123)
            ])
            old_messages = data.messages
            old_message = old_messages[0]
            state = websocket.WebSocketData([
                websocket.WebSocketMessage(2, False, b'new', timestamp=456)
            ]).get_state()
            if variant == 'missing':
                del state['close_reason']
            elif variant == 'extra':
                state['unknown'] = 1
            error_name = None
            try:
                if operation == 'set':
                    data.set_state(state)
                else:
                    data = websocket.WebSocketData.from_state(state)
            except Exception as error:
                error_name = type(error).__name__
            results[operation + '/' + variant] = {
                'error': error_name, 'state': normalize(data.get_state()),
                'input_after': normalize(state),
                'same_list': data.messages is old_messages,
                'same_message': data.messages[0] is old_message,
            }
    return results

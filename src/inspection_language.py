"""Bounded static editor queries. Never compile or execute the submitted script."""

def language_prelude():
    import json
    lines = ['from typing import Any']
    for name, definition in api_schema()['types'].items():
        lines += [f'class {name}:', '    ' + json.dumps(definition['description'])]
        for field in definition['fields']:
            # Properties give Jedi both a return type and a docstring for aliases.
            lines += ['    @property', f'    def {field["name"]}(self) -> {field["type"]}:',
                '        ' + json.dumps(field['description'] + '\n\n' + field['availability'] +
                    '\n\nExample:\n' + field['example']), '        ...']
    lines += ['class SpiderApi(InspectionViews):',
        '    bytes: bytes', '    text: str', '    side: str', '    session_id: str',
        '    session_label: str', '    event: dict[str, Any]', '    info: dict[str, Any]',
        '    annotations: list[Any]', '    enrichments: list[Any]',
        '    l7_state: str', '    l7_bytes: bytes', '    l7_ranges: list[tuple[int, int]]',
        '    l7_encodings: list[str]',
        '    def print(self, *values: Any) -> None:',
        '        """Append values to script output."""', '        ...',
        '    def hexdump(self, limit: int = 256, width: int = 16) -> str:',
        '        """Preview original bytes; limit bounds output, width sets bytes per row."""',
        '        ...', 'def __spider_script(api: SpiderApi):']
    return '\n'.join(lines) + '\n'


def language_query(request):
    try:
        import jedi
    except ImportError:
        return {'ok': False, 'error': 'Static Python help requires Jedi in the backend Python environment.'}
    import tempfile
    previous_cache = jedi.settings.cache_directory
    with tempfile.TemporaryDirectory(prefix='spider-language-') as cache:
        jedi.settings.cache_directory = cache
        try:
            return _language_query(request, jedi)
        finally:
            jedi.settings.cache_directory = previous_cache


def _language_query(request, jedi):
    import ast
    source = request.get('script', '')
    action = request.get('language_action')
    line, column = request.get('line'), request.get('column')
    if not isinstance(source, str) or len(source.encode()) > 65536:
        raise ValueError('script exceeds 64 KiB')
    lines = source.split('\n')
    if type(line) is not int or type(column) is not int or not 1 <= line <= len(lines) or not 0 <= column <= len(lines[line - 1]):
        raise ValueError('invalid cursor position')
    if action not in ('complete', 'hover', 'signature', 'diagnostics'):
        raise ValueError('invalid language action')
    prelude = language_prelude()
    wrapped = prelude + '\n'.join('    ' + part for part in lines)
    prefix = prelude.count('\n')
    jedi.settings.fast_parser = False
    jedi.settings.auto_import_modules = []
    script = jedi.Script(wrapped)
    position = (prefix + line, column + 4)
    def describe(item):
        return {'label': item.name, 'type': item.type,
                'detail': item.description[:500], 'info': item.docstring()[:6000]}
    if action == 'complete':
        return {'ok': True, 'items': [describe(item) for item in script.complete(*position)[:100]]}
    if action == 'hover':
        items = script.infer(*position) + script.goto(*position)
        descriptions = []
        for item in items:
            description = describe(item)
            if description not in descriptions:
                descriptions.append(description)
        return {'ok': True, 'items': descriptions[:4]}
    if action == 'signature':
        return {'ok': True, 'items': [{'label': item.to_string(), 'index': item.index,
            'info': item.docstring()[:6000]} for item in script.get_signatures(*position)[:4]]}
    # Syntax diagnostics only: Jedi is not a full type checker.
    diagnostics = []
    try:
        ast.parse(wrapped)
    except SyntaxError as error:
        row = (error.lineno or 1) - prefix
        if 1 <= row <= len(lines):
            diagnostics.append({'line': row, 'column': max(0, (error.offset or 5) - 5),
                                'message': error.msg})
    return {'ok': True, 'diagnostics': diagnostics}

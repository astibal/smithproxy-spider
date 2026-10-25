"""Render the complete schema example inventory; --check rejects stale docs."""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from inspection_api import api_schema


def render():
    schema = api_schema()
    lines = [
        '# API examples: úplný inventář', '',
        'Generováno pomocí `python3 tools/generate-api-examples.py`; neupravuj ručně.', '',
        '[Praktické scénáře a očekávané chyby](INSPECTION_COOKBOOK.md).', '',
        'Tyto mikro-příklady pokrývají každý veřejný člen typovaného schematu.',
        '`api` poskytuje callback. Příklady s `part` předpokládají vybraný H2',
        'HEADERS part s dekódovanými hlavičkami; `entry` je jeho HPACK položka.',
        'Nejde o jeden souvislý skript: každý blok je samostatná ukázka.', '',
    ]
    for name, definition in schema['types'].items():
        lines.extend([f'## {name}', '', definition['description'] or '', ''])
        members = definition['fields'] + definition['methods']
        if not members:
            lines.extend(['Typ bez veřejných členů ve schematu; praktické použití je v cookbooku.', ''])
        for member in members:
            lines.extend([
                f"### {name}.{member['name']}", '', member['description'], '',
                f"Dostupnost: {member['availability']}", '',
                f"Přístup: {member['access']}; typ/výsledek: `{member['type']}`.", '',
                '```python', member['example'], '```', '',
            ])
    return '\n'.join(lines)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    target = ROOT / 'docs/API_EXAMPLES_REFERENCE.md'
    content = render()
    if args.check:
        if not target.exists() or target.read_text() != content:
            raise SystemExit('API example inventory is stale; run tools/generate-api-examples.py')
    else:
        target.write_text(content)

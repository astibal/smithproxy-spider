"""Build artifact: introspect the same API definitions embedded in the worker."""
import json
import pathlib
import runpy
import sys

module = runpy.run_path(sys.argv[1])
schema = module['api_schema']()
for entry in schema['types'].values():
    for field in entry['fields']:
        assert field['description'] and field['example'] and field['availability']
pathlib.Path(sys.argv[2]).write_text(
    '#pragma once\ninline constexpr const char* inspection_schema_json = R"SCHEMA('
    + json.dumps(schema) + ')SCHEMA";\n')

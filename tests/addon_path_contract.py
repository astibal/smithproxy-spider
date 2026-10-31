"""Black-box URL path-component view and mutation cases."""


def collect(request_type):
    results = {}
    paths = ('/', '', '//', '/a//b/', '//a/b', '/a;b/c;d?x=1#fragment',
             '/%2F/%25/%20', '/%ff/%C3%A9', '/a?x=/b#end', '*',
             'https://other.test/a/b?q=1', '/a/../b/./c', '/a+b')
    replacements = (None, (), ('one', 'two'), ('a/b', 'x y', 'a+b'),
                    ('', 'middle', ''), ('café',), ('a?b#c;d',), ('\udcff',),
                    ('%2f',), (3,))
    for index, path in enumerate(paths):
        for change, components in enumerate(replacements):
            request = request_type.make('GET', 'https://example.test/')
            request.path = path
            error = None
            before = None
            after = None
            try:
                before = list(request.path_components)
                if components is not None:
                    request.path_components = components
                after = list(request.path_components)
            except Exception as failure:
                error = type(failure).__name__
            results[f'{index}/{change}'] = {
                'input': path, 'components': components,
                'before': before, 'after': after,
                'path': request.path, 'error': error,
            }
    return results

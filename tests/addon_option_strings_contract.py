"""Black-box cases for the public string-based option configuration API."""

from typing import Optional, Sequence


def collect(factory):
    results = {}
    cases = [
        (), ('flag',), ('flag=true',), ('flag=false',), ('flag=toggle',),
        ('flag=True',), ('flag=1',), ('flag=',), ('count',), ('count=',),
        ('count=42',), ('count=-2',), ('count=0x10',), ('count= 3 ',),
        ('label',), ('label=',), ('label=a=b',), ('maybe',), ('maybe=',),
        ('maybe=None',), ('names',), ('names=',), ('names=one', 'names=two'),
        ('names=a,b',), ('count=2', 'count=3'), ('flag=toggle', 'flag=toggle'),
        ('count=2', 'missing=3'), ('count=2', 'flag=invalid'),
        ('missing',), (' count=2',), ('',), ('label= a ',),
        ('number',), ('number=',), ('number=2',), ('number=None',),
        ('count=2', 'label=changed', 'flag'), ('flag=false', 'label='),
    ]
    for index, specs in enumerate(cases):
        options = factory()
        options.add_option('flag', bool, False, 'Flag')
        options.add_option('count', int, 1, 'Count')
        options.add_option('label', str, 'original', 'Label')
        options.add_option('maybe', Optional[str], 'original', 'Optional label')
        options.add_option('number', Optional[int], 1, 'Optional number')
        options.add_option('names', Sequence[str], ['original'], 'Names')
        notifications = []

        def changed(updated):
            notifications.append(sorted(updated))

        options.changed.connect(changed)
        error = None
        try:
            options.set(*specs)
        except Exception as failure:
            error = type(failure).__name__
        results[str(index)] = {
            'specs': list(specs), 'error': error,
            'values': {name: getattr(options, name) for name in sorted(options.keys())},
            'notifications': notifications,
        }
    return results

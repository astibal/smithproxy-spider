"""Adversarial public flow-filter parser observations.

The expressions are original test inputs.  They exercise documented syntax
boundaries without inspecting the reference implementation.
"""


EXPRESSIONS = (
    "~all",
    "!!~all",
    "! ! ~all",
    "~q ~m GET ~d example",
    "~q & ~m GET & ~d example",
    "~q | ~s & ~m GET",
    "( ~q | ~s ) & ! ~e",
    "! ( ~q | ( ~s & ~e ) )",
    "~u 'path with spaces'",
    '~u "get(Info|Routers)"',
    '~u "literal~tilde"',
    '~u "escaped\\\"quote"',
    "~u 'escaped\\'quote'",
    "~u café",
    "~u 😀",
    "~u ^https://example\\.test/[a-z]+$",
    "~h 'x-name: value with spaces'",
    "~meta '^key: value$'",
    "~comment 'first\\nsecond'",
    "~comment 'first\\tsecond'",
    "~comment 'first\\\\second'",
    "~comment 'first\\qsecond'",
    "~comment 'first\\x41second'",
    "~comment 'first\\u0041second'",
    "~comment 'trailing\\'",
    "bare-pattern",
    "bare pattern second",
    "bare\\s+pattern",
    "~m GET&~q",
    "~m GET| ~s",
    "~q &~m GET",
    "( ~q )&~s",
    "",
    " ",
    "\t",
    "!",
    "&",
    "|",
    "()",
    "( )",
    "(~q)",
    "( ~q",
    "~q )",
    "~q |",
    "~q &",
    "~q || ~s",
    "~q && ~s",
    "~q ||",
    "~q &&",
    "||",
    "&&",
    "~u",
    "~u ''",
    '~u ""',
    "~u 'unfinished",
    '~u "unfinished',
    "~u [",
    "~c -1",
    "~c +1",
    "~c 001",
    "~c 200x",
    "~c 200.5",
    "~c 200~q",
    "~unknown value",
)


def collect(flowfilter):
    observations = {}
    for expression in EXPRESSIONS:
        key = repr(expression)
        try:
            parsed = flowfilter.parse(expression)
            observations[key] = {
                "type": type(parsed).__name__,
                "description": str(parsed),
            }
        except Exception as error:
            observations[key] = {
                "error": type(error).__name__,
                "message": str(error),
            }
    return observations

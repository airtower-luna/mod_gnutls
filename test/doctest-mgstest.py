#!/usr/bin/python3

if __name__ == "__main__":
    import doctest
    import importlib
    import sys
    modules = [
        'mgstest',
        'mgstest.hooks',
        'mgstest.http',
        'mgstest.services',
        'mgstest.softhsm',
        'mgstest.tests'
    ]

    totals = (0, 0)
    for m in modules:
        mod = importlib.import_module(m)
        result = doctest.testmod(m=mod, verbose=True)
        totals = tuple(sum(x) for x in zip(totals, result))

    fails, count = totals
    print(f'Summary over all modules: {fails} out of {count} tests failed.')
    if fails > 0:
        sys.exit(1)

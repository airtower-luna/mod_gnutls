#!/usr/bin/python3
import doctest
import importlib
import sys
from pathlib import Path

if __name__ == "__main__":
    modules = set()
    for p in Path('mgstest').glob('**/*.py'):
        if p.stem == '__init__':
            modules.add('.'.join(p.parts[:-1]))
        else:
            modules.add('.'.join((*p.parts[:-1], p.stem)))

    totals = (0, 0)
    for m in modules:
        mod = importlib.import_module(m)
        result = doctest.testmod(m=mod, verbose=True)
        totals = tuple(sum(x) for x in zip(totals, result))

    fails, count = totals
    print(f'Summary over all modules: {fails} out of {count} tests failed.')
    if fails > 0:
        sys.exit(1)

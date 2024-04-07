#!/usr/bin/python3
import doctest
import importlib
import mgstest
import pkgutil
import sys

if __name__ == "__main__":
    fails, count = (0, 0)
    for m in pkgutil.walk_packages(mgstest.__path__, mgstest.__name__ + '.'):
        mod = importlib.import_module(m.name)
        result = doctest.testmod(m=mod, verbose=True)
        fails += result[0]
        count += result[1]

    print(f'Summary over all modules: {fails} out of {count} tests failed.')
    if count < 1 or fails > 0:
        sys.exit(1)

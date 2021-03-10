#!/usr/bin/python3
import os
import sys
import unittest

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(
        'mgstest', top_level_dir=os.environ.get('srcdir', '.'))
    result = unittest.TextTestRunner(verbosity=2, buffer=True).run(suite)
    if not result.wasSuccessful():
        sys.exit(1)

import os
from unittest import SkipTest

def prepare_env():
    if 'MSVA_PORT' not in os.environ:
        raise SkipTest('Build without MSVA support.')
    os.environ['USE_MSVA'] = 'yes'

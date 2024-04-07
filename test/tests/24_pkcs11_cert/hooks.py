#!/usr/bin/python3
import os
import mgstest.softhsm
from pathlib import Path
from unittest import SkipTest


def prepare_env():
    if not mgstest.softhsm.find_softhsm_bin():
        raise SkipTest('SoftHSM not found.')

    db = Path(os.environ['builddir']) / 'authority/server/softhsm2.db'
    softhsm_conf = mgstest.softhsm.tmp_softhsm_conf(db)

    def cleanup():
        print(f'Delete {softhsm_conf}')
        Path(softhsm_conf).unlink()

    try:
        token = mgstest.softhsm.Token(config_file=softhsm_conf)
        for key, value in token.test_env.items():
            os.environ[key] = value
    except Exception:
        cleanup()
        raise

    return cleanup

#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK

# Copyright 2020 Fiona Klute
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import mgstest.softhsm
import shutil
from pathlib import Path

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Initialize a SoftHSM test token')
    parser.add_argument('--token-dir', type=str, required=True,
                        help='private key to store in the token')
    parser.add_argument('--privkey', type=str, required=True,
                        help='private key to store in the token')
    parser.add_argument('--certificate', type=str, default=None,
                        help='certificate to store in the token')

    # enable bash completion if argcomplete is available
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    softhsm_conf = mgstest.softhsm.tmp_softhsm_conf(args.token_dir)
    try:
        token = mgstest.softhsm.Token(config_file=softhsm_conf)
        token.reset_db()
        token.init_token()
        token.store_key(args.privkey, mgstest.softhsm.test_label)
        if args.certificate:
            token.store_cert(args.certificate, mgstest.softhsm.test_label)
    except:
        # Don't leave a half-done token around, the next make call
        # only checks the directory and would assume it's done.
        shutil.rmtree(args.token_dir)
        raise
    finally:
        Path(softhsm_conf).unlink()

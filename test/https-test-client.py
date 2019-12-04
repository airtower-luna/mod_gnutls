#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK

# Copyright 2019 Fiona Klute
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

import yaml

from mgstest.tests import TestConnection

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Send HTTP requests through gnutls-cli',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('host', nargs='?', help='Access the specified host',
                        default='localhost')
    parser.add_argument('-p', '--port', type=int,
                        help='Access the specified port', default='8000')
    parser.add_argument('--test-config', type=argparse.FileType('r'),
                        required=True, help='load YAML test configuration')

    # enable bash completion if argcomplete is available
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    conns = None

    config = yaml.load(args.test_config, Loader=yaml.Loader)
    if type(config) is TestConnection:
        conns = [config]
    elif type(config) is list:
        # assume list elements are connections
        conns = config
    else:
        raise TypeError(f'Unsupported configuration: {config!r}')
    print(conns)

    for test_conn in conns:
        test_conn.run(host=args.host, port=args.port)

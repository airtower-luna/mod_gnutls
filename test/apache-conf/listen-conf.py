import os
import sys
from textwrap import dedent

assert 'TEST_IP' in os.environ

listen_lines = '\n'.join(
    f'Listen {ip}:${{TEST_PORT}}' for ip in os.environ['TEST_IP'].split())

with open(sys.argv[1], 'w') as fh:
    print(
        os.linesep.join(
            f'Listen {ip}:${{TEST_PORT}}'
            for ip in os.environ['TEST_IP'].split()),
        file=fh)
    print('<IfDefine TEST_HTTP_PORT>', file=fh)
    print(
        os.linesep.join(
            f'    Listen {ip}:${{TEST_HTTP_PORT}}'
            for ip in os.environ['TEST_IP'].split()),
        file=fh)
    print('</IfDefine>', file=fh)

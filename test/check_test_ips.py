#!/usr/bin/python3

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

"""Usage: python3 check_test_ips.py IP|HOSTNAME [...]

Check if the given IPs, or IPs associated with given hostnames, are
routable. Under the assumption that those IPs are local a positive
result means they should be usable for tests.

The script prints the first two (in order of arguments) usable
addresses to sys.stdout. IPv6 addresses in the output are enclosed in
square brackets.

"""
import socket
import sys


def try_connect(sockaddr):
    """Try to connect a UDP socket to the given address. "Connecting" a
    UDP socket means only setting the default destination for packets,
    so nothing is actually sent. Return True if the socket.connect()
    call was successful, False otherwise.

    For loopback this effectively tests if the address is really
    configured, to detect e.g. situations where a system may have "::1
    localhost" in /etc/hosts, but actually has IPv6 disabled.

    """
    af, socktype, proto, canonname, sa = sockaddr
    try:
        s = socket.socket(af, socktype, proto)
        s.connect(sa)
    except:
        return False
    finally:
        s.close()
    return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Check if IPs/hostnames are routable')
    parser.add_argument('hosts', metavar='HOST', nargs='+',
                        help='the hostnames/IPs to check')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='disable debug output')
    parser.add_argument('--hostname', '-H', action='store_true',
                        help='append socket.gethostname() to hosts')
    args = parser.parse_args()

    if args.hostname:
        args.hosts.append(socket.gethostname())

    test_ips = []
    for name in args.hosts:
        addrs = list(map(lambda t: t[-1][0],
                         filter(try_connect,
                                socket.getaddrinfo(name, 12345,
                                                   proto=socket.IPPROTO_UDP))))
        if not args.quiet:
            print(f'{name}: {addrs}', file=sys.stderr)
        test_ips += addrs

    print(' '.join(f'[{i}]' if ':' in i else i for i in test_ips[:2]))

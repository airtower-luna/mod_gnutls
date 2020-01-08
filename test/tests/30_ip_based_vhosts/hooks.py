import os
from unittest import SkipTest

def prepare_env():
    addrs = os.environ['TEST_IP'].split()
    if len(addrs) < 2:
        raise SkipTest('This test needs two or more IP addresses in '
                       'TEST_IP, check ./configure options!')

    # The two virtual hosts have different IPs, so we can check if
    # selection without SNI works correctly. The request will go to the
    # second one.
    os.environ['VHOST1_IP'] = addrs[0]
    os.environ['VHOST2_IP'] = addrs[1]

    # gnutls-cli expects IPv6 addresses without enclosing brackets,
    # remove them
    os.environ['TARGET_IP'] = addrs[1].strip('[]')

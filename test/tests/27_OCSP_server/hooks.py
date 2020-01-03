import re
from mgstest import require_match

def post_check(conn_log, response_log):
    print('Checking if the client actually got a stapled response:')
    print(require_match(re.compile(r'^- Options: .*OCSP status request,'),
                        conn_log).group(0))

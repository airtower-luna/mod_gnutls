import re
from mgstest import require_match


def post_check(conn_log, response_log):
    print('Checking if the session was resumed successfully...')
    # NOTE: The "Resume Handshake was completed" message appears after
    # the second handshake is complete, whether the session has been
    # resumed or not. The following message is required!
    print(require_match(re.compile(r'^\*\*\* This is a resumed session\b'),
                        conn_log).group(0))

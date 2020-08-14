import re
from mgstest import require_match, TestExpectationFailed
from pathlib import Path


LOGFILE = Path('logs/37_TLS_reverse_proxy_resume_session.backend.error.log')
LOGFILE_POSITION = 0


def prepare_env():
    # Seek to the end of server log, if it exists from previous tests
    if LOGFILE.exists():
        global LOGFILE_POSITION
        LOGFILE_POSITION = LOGFILE.stat().st_size


def post_check(conn_log, response_log):
    conn_opened = re.compile(r'tid (\d+)\].* TLS connection opened.')
    session_resumed = re.compile(r'tid (\d+)\].* TLS session resumed.')

    print('Checking if the backend server log contains session resumption')
    with LOGFILE.open() as log:
        print(f'Seeking to position {LOGFILE_POSITION}')
        log.seek(LOGFILE_POSITION)

        require_match(conn_opened, log)
        print('Initial session found.')

        id1 = require_match(session_resumed, log).group(1)
        id2 = require_match(conn_opened, log).group(1)
        if id1 != id2:
            raise TestExpectationFailed(
                'thread ID mismatch between resume and open message: '
                f'{id1} != {id2}')
        print('Resumed session found.')

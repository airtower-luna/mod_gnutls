import re
from mgstest import require_match
from pathlib import Path


LOGFILE = Path('logs/37_TLS_reverse_proxy_resume_session.backend.error.log')
LOGFILE_POSITION = 0


def prepare_env():
    # Seek to the end of server log, if it exists from previous tests
    if LOGFILE.exists():
        global LOGFILE_POSITION
        LOGFILE_POSITION = LOGFILE.stat().st_size


def post_check(conn_log, response_log):
    conn_opened = re.compile(r'TLS connection opened.')
    conn_closed = re.compile(r'TLS connection closed.')
    session_resumed = re.compile(r'TLS session resumed.')

    print('Checking if the backend server log contains session resumption')
    with LOGFILE.open() as log:
        print(f'Seeking to position {LOGFILE_POSITION}')
        log.seek(LOGFILE_POSITION)

        require_match(conn_opened, log)
        require_match(conn_closed, log)
        print('Initial session found.')

        require_match(session_resumed, log)
        require_match(conn_opened, log)
        require_match(conn_closed, log)
        print('Resumed session found.')

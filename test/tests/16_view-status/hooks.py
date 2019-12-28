from mgstest import first_line_match, TestExpectationFailed
import re

def post_check(conn_log, response_log):
    """Compare the TLS session information reported by gnutls-cli and the
    mod_gnutls status listing."""

    # Group 1 is the TLS version, group 2 the ciphers. The certificate
    # type that may be enclosed in the same brackets as the TLS
    # version is ignored.
    re_session = '\((TLS[\d\.]+).*?\)-(.*)'

    # Prefix for gnutls-cli output
    re_cli = re.compile('(?<=^-\sDescription:\s)' + re_session + '$')
    # Prefix in mod_status output provided by mod_gnutls
    re_status = re.compile('(?<=^Current TLS session:\s)' + re_session + '$')

    cli_suite = first_line_match(re_cli, conn_log)
    if not cli_suite:
        raise TestExpectationFailed(
            'Client cipher suite information is missing!')
    status_suite = first_line_match(re_status, response_log)
    if not status_suite:
        raise TestExpectationFailed(
            'Server cipher suite information is missing!')

    print(f'Client session info: {cli_suite.group(0)}')
    print(f'Server session info: {status_suite.group(0)}')

    if cli_suite.group(1) != status_suite.group(1):
        raise TestExpectationFailed(
            f'Client ({cli_suite.group(1)}) and server '
            f'({status_suite.group(1)}) report different protocols!')

    if cli_suite.group(2) != status_suite.group(2):
        raise TestExpectationFailed(
            f'Client ({cli_suite.group(2)}) and server '
            f'({status_suite.group(2)}) report different ciphers!')

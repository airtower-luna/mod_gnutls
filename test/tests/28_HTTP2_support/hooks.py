import os
import subprocess

def run_connection(testname, conn_log, response_log):
    url = f'https://{os.environ["TEST_HOST"]}:{os.environ["TEST_PORT"]}' \
        '/status?auto'
    command = [os.environ['HTTP_CLI'], '--http2', '--location', '--verbose',
               '--cacert', 'authority/x509.pem', url]

    proc = subprocess.run(command,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True, text=True)
    print(proc.stderr)
    print(proc.stderr, file=conn_log)
    print(proc.stdout)
    print(proc.stdout, file=response_log)

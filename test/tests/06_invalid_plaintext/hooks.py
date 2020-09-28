import contextlib
import os
import re
import socket
import ssl
import struct

from urllib.request import urlopen

CRLF = b'\r\n\r\n'


class TLSRecord:
    header = struct.Struct('!BHH')
    def __init__(self, data):
        self.type, self.legacy_proto, self.length = \
            self.header.unpack(data[:5])
        self.data = data[5:]
        if len(self.data) != self.length:
            raise ValueError('Actual data length does not match header!')

    def __repr__(self):
        return f'<{__name__}.{self.__class__.__name__}, type: {self.type}>'

    @property
    def is_alert(self):
        return self.type == 21

    @property
    def is_app_data(self):
        return self.type == 23


def test_immediate_plaintext(host, port, req):
    """Send plaintext to the HTTPS socket"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(req)
        data = s.recv(1024)
    print(f'Received: {data!r}')
    record = TLSRecord(data)
    # Expect an unencrypted alert
    assert(record.is_alert)
    assert(record.length == 2)


def test_plaintext_after_https(host, port, req, context):
    """Send an HTTPS request and then plaintext on the same TCP connection"""
    with contextlib.ExitStack() as stack:
        s = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        s.connect((host, port))

        # Duplicate s so we can still use it.
        tls_sock = stack.enter_context(
            context.wrap_socket(s.dup(), server_hostname='localhost',
                                do_handshake_on_connect=False,
                                suppress_ragged_eofs=False))
        tls_sock.do_handshake()

        # Send request
        tls_sock.sendall(req)

        # Read header
        buf = bytearray(2048)
        pos = 0
        while not CRLF in buf:
            received = tls_sock.recv_into(memoryview(buf)[pos:])
            # If we get 0 it means the connection ended before the
            # header was complete.
            assert(received > 0)
            pos += received
        print(f'Received HTTPS header: {bytes(memoryview(buf)[:pos])!r}')
        data_start = buf.index(CRLF) + len(CRLF)

        # Read body
        m = re.search(rb'\r\nContent-Length: (\d+)\r\n', buf)
        assert(m is not None)
        clen = int(m.group(1))
        while pos < (data_start + clen):
            received = tls_sock.recv_into(memoryview(buf)[pos:])
            # If we get 0 it means the connection ended before the
            # body was complete.
            assert(received > 0)
            pos += received
        body_data = bytes(memoryview(buf)[data_start:pos])
        print(f'Received HTTPS data: {body_data!r}')
        assert(body_data == b'test\n')

        print('Sending plaintext request')
        s.sendall(req)
        # Peek read so the TLS socket can also get the alert.
        data = s.recv(1024, socket.MSG_PEEK)
        print(f'Received: {data!r}')
        record = TLSRecord(data)
        # Expect application data (TLS 1.3 encrypted alert, hopefully)
        assert(record.is_app_data)
        assert(record.length > 2)

        tls_sock.sendall(req)
        data = tls_sock.recv(clen)
        print(f'Received TLS data: {data!r}')
        assert(len(data) == 0)
        print('Connection has been closed as expected.')


def run_connection(testname, conn_log, response_log):
    """Inject unencrypted requests into TCP connections."""

    host = os.environ['TEST_HOST']
    port = int(os.environ['TEST_PORT'])
    http_req = f'GET /test.txt HTTP/1.1\r\nHost: {host}\r\n\r\n'.encode()

    context = ssl.SSLContext()
    context.load_verify_locations(cafile='authority/x509.pem')
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    print(test_immediate_plaintext.__doc__)
    test_immediate_plaintext(host, port, http_req)
    print()

    print(test_plaintext_after_https.__doc__)
    test_plaintext_after_https(host, port, http_req, context)
    print()

    print('Send a good HTTPS request, and expect it to work')
    with urlopen(f'https://{host}:{port}/test.txt', context=context) as f:
        print(f.read().decode())


if __name__ == '__main__':
    run_connection(None, None, None)

import unittest
from http import HTTPStatus
from unittest.mock import Mock, patch

from . import TestExpectationFailed
from .tests import TestRequest


def mock_response(status=HTTPStatus.OK, headers=dict(), body=b''):
    response = Mock()
    response.status = status
    response.reason = status.phrase
    response.getheaders.return_value = [(k, v) for k, v in headers.items()]
    response.read.return_value = body
    return response


class TestTestRequest(unittest.TestCase):
    def test_run(self):
        """Check that TestRequest matches regular response correctly."""
        response = mock_response(
            HTTPStatus.OK, {'X-Required-Header': 'Hi!'}, b'Hello World!\n')
        conn = Mock()
        conn.getresponse.return_value = response

        r = TestRequest(path='/test.txt',
                        expect={'status': 200,
                                'headers': {'X-Forbidden-Header': None,
                                            'X-Required-Header': 'Hi!'},
                                'body': {'contains': 'Hello'}})
        r.run(conn)
        conn.request.assert_called_with(
            'GET', '/test.txt', body=None, headers={})

    def test_run_unexpected_reset(self):
        """An unexpected exception breaks out of the TestRequest run."""
        conn = Mock()
        conn.request.side_effect = ConnectionResetError
        r = TestRequest(path='/test.txt',
                        expect={'status': 200})
        with self.assertRaises(ConnectionResetError):
            r.run(conn)
        conn.request.assert_called_with(
            'GET', '/test.txt', body=None, headers={})

    def test_run_expected_reset(self):
        """If the TestRequest expects an exception, it gets caught."""
        conn = Mock()
        conn.request.side_effect = ConnectionResetError
        r = TestRequest(path='/test.txt',
                        expect={'reset': True})
        r.run(conn)
        conn.request.assert_called_with(
            'GET', '/test.txt', body=None, headers={})

    def test_check_headers(self):
        r = TestRequest(path='/test.txt',
                        expect={'headers': {'X-Forbidden-Header': None,
                                            'X-Required-Header': 'Hi!'}})
        r.check_headers({'X-Required-Header': 'Hi!'})

        with self.assertRaisesRegex(TestExpectationFailed,
                                    'Unexpected value in header'):
            r.check_headers({'X-Required-Header': 'Hello!'})

        with self.assertRaisesRegex(TestExpectationFailed,
                                    'Unexpected value in header'):
            r.check_headers({'X-Forbidden-Header': 'Hi!'})

    def test_check_body_exact(self):
        r = TestRequest(
            path='/test.txt', method='GET', headers={},
            expect={'status': 200, 'body': {'exactly': 'test\n'}})
        r.check_body('test\n')

        with self.assertRaisesRegex(
                TestExpectationFailed,
                r"Unexpected body: 'xyz\\n' != 'test\\n'"):
            r.check_body('xyz\n')

    def test_check_body_contains(self):
        r1 = TestRequest(
            path='/test.txt', method='GET', headers={},
            expect={'status': 200, 'body': {'contains': ['tes', 'est']}})
        r1.check_body('test\n')
        with self.assertRaisesRegex(
                TestExpectationFailed,
                r"Unexpected body: 'est\\n' does not contain 'tes'"):
            r1.check_body('est\n')

        r2 = TestRequest(
            path='/test.txt', method='GET', headers={},
            expect={'status': 200, 'body': {'contains': 'test'}})
        r2.check_body('test\n')

    def test_expects_conn_reset(self):
        r1 = TestRequest(path='/test.txt', method='GET', headers={},
                         expect={'status': 200, 'body': {'contains': 'test'}})
        self.assertFalse(r1.expects_conn_reset())

        r2 = TestRequest(path='/test.txt', method='GET', headers={},
                         expect={'reset': True})
        self.assertTrue(r2.expects_conn_reset())

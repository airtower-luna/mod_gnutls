import unittest
import unittest.mock
import yaml
from http import HTTPStatus

from . import TestExpectationFailed
from .tests import TestRequest


def mock_response(status=HTTPStatus.OK, headers=dict(), body=b''):
    response = unittest.mock.Mock()
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
        conn = unittest.mock.Mock()
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
        conn = unittest.mock.Mock()
        conn.request.side_effect = ConnectionResetError
        r = TestRequest(path='/test.txt',
                        expect={'status': 200})
        with self.assertRaises(ConnectionResetError):
            r.run(conn)
        conn.request.assert_called_with(
            'GET', '/test.txt', body=None, headers={})

    def test_run_expected_reset(self):
        """If the TestRequest expects an exception, it gets caught."""
        conn = unittest.mock.Mock()
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


class TestTestConnection(unittest.TestCase):
    def test_run(self):
        """TestConnection with a successful and a failing TestRequest."""

        test = """
        !connection
        gnutls_params:
          - x509cafile=authority/x509.pem
        actions:
          - !request
            path: /test.txt
            headers:
              X-Test: mgstest
            expect:
              status: 200
              headers:
                X-Required: 'Hi!'
              body:
                exactly: |
                  Hello World!
          - !request
            method: POST
            path: /test.txt
            expect:
              status: 200
              body:
                exactly: |
                  Hello World!
        """
        conn = yaml.load(test, Loader=yaml.Loader)

        responses = [
            mock_response(
                HTTPStatus.OK, {'X-Required': 'Hi!'},
                b'Hello World!\n'),
            mock_response(
                HTTPStatus.METHOD_NOT_ALLOWED, {}, b'Cannot POST here!\n')]

        # note that this patches HTTPSubprocessConnection as imported
        # into mgstest.tests, not in the origin package
        with unittest.mock.patch(
                'mgstest.tests.HTTPSubprocessConnection', spec=True) as P:
            # the mock provided by patch acts as class, get the instance
            instance = P.return_value
            instance.getresponse.side_effect = responses
            with self.assertRaisesRegex(
                    TestExpectationFailed,
                    r"Unexpected status: 405 != 200"):
                conn.run()

        instance.request.assert_has_calls([
            unittest.mock.call(
                'GET', '/test.txt', body=None, headers={'X-Test': 'mgstest'}),
            unittest.mock.call('POST', '/test.txt', body=None, headers={})
        ])
        self.assertEqual(instance.request.call_count, 2)

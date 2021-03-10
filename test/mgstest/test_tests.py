import unittest
from . import TestExpectationFailed
from .tests import TestRequest


class TestTestRequest(unittest.TestCase):
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

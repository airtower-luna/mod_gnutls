import mgstest


def prepare_env():
    mgstest.require_apache_modules('mod_http2.so', 'mod_proxy_http2.so')

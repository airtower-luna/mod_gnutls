# Copyright 2020 Fiona Klute
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""SoftHSM support for testing mod_gnutls' PKCS#11 features."""

import os
import re
import shutil
import subprocess
import tempfile
from enum import Enum
from pathlib import Path

softhsm_libname = 'libsofthsm2.so'
# common install locations to search for the libsofthsm2 PKCS#11 module
softhsm_searchpath = [
    Path('/usr/lib64/pkcs11'),
    Path('/usr/lib/softhsm'),
    Path('/usr/lib64/softhsm'),
    Path('/usr/lib/x86_64-linux-gnu/softhsm'),
    Path('/usr/lib')
]

# token directory setting in token config file
tokendir_re = re.compile(r'^directories\.tokendir\s*=\s*(.*)$')

test_label = 'test_server'

class ObjectType(Enum):
    """Types that may occur in PKCS#11 URIs (type=...).

    See: https://tools.ietf.org/html/rfc7512#section-2.3

    """
    CERT = 'cert'
    DATA = 'data'
    PRIVATE = 'private'
    PUBLIC = 'public'
    SECRET_KEY = 'secret-key'

    def __init__(self, uri_type):
        self.uri_type = uri_type

    def __str__(self):
        """
        >>> str(ObjectType.CERT)
        'type=cert'
        """
        return f'type={self.uri_type}'

    def __repr__(self):
        """
        >>> repr(ObjectType.PRIVATE)
        'ObjectType.PRIVATE'
        """
        return f'{self.__class__.__name__!s}.{self.name}'

class Token:
    """Represents a PKCS#11 token."""
    def __init__(self, config_file, label='mod_gnutls-test'):
        """The config_file is what SoftHSM expects as SOFTHSM2_CONF."""
        self.config = config_file
        self.label = label
        # Fixed defaults (for now?)
        # SO -> security officer
        self.so_pin = '123456'
        # export as GNUTLS_PIN for use with GnuTLS tools
        self.pin = '1234'

        # get tokendir from config file
        self.tokendir = None
        with open(self.config) as fh:
            for line in fh:
                m = tokendir_re.fullmatch(line.strip())
                if m:
                    self.tokendir = Path(m.group(1))
                    break

        self.softhsm = find_softhsm_bin()
        self.softhsm_lib = find_softhsm_lib()

        # GnuTLS PKCS#11 tool, currently taken from PATH
        self.p11tool = ['p11tool', '--provider', self.softhsm_lib]
        # Lazy initialization
        self._token_url = None
        self._object_listing = None

    def reset_db(self):
        """Delete the SoftHSM database directory, and recreate it."""
        if self.tokendir.exists():
            shutil.rmtree(self.tokendir)
        self.tokendir.mkdir()

    def init_token(self):
        """Initialize a token. The SoftHSM database directory must already
        exist."""
        subprocess.run([self.softhsm, '--init-token',
                        '--free', '--label', self.label,
                        '--so-pin', self.so_pin, '--pin', self.pin],
                       check=True, env={'SOFTHSM2_CONF': self.config})

    @property
    def token_url(self):
        if not self._token_url:
            proc = subprocess.run(self.p11tool + ['--list-token-urls'],
                                  stdout=subprocess.PIPE, check=True, text=True,
                                  env={'SOFTHSM2_CONF': self.config})
            url_re = re.compile(f'^pkcs11:.*token={self.label}\\b.*$')
            for line in proc.stdout.splitlines():
                if url_re.fullmatch(line):
                    self._token_url = line
                    break
        return self._token_url

    @property
    def p11tool_env(self):
        return {'SOFTHSM2_CONF': self.config, 'GNUTLS_PIN': self.pin}

    def store_key(self, keyfile, label):
        """Store a private key in this token."""
        subprocess.run(self.p11tool +
                       ['--login', '--write', '--label', label,
	                '--load-privkey', keyfile, self.token_url],
                       check=True, text=True, env=self.p11tool_env)
        self._object_listing = None

    def store_cert(self, certfile, label):
        """Store a certificate in this token."""
        subprocess.run(self.p11tool +
                       ['--login', '--write', '--no-mark-private',
                        '--label', label,
	                '--load-certificate', certfile, self.token_url],
                       check=True, text=True, env=self.p11tool_env)
        self._object_listing = None

    def get_object_url(self, label, type):
        """Get the PKCS#11 URL for an object in this token, selected by
        label."""
        if not self._object_listing:
            proc = subprocess.run(self.p11tool +
                                  ['--login', '--list-all', self.token_url],
                                  stdout=subprocess.PIPE,
                                  check=True, text=True, env=self.p11tool_env)
            self._object_listing = proc.stdout.splitlines()
        object_re = re.compile(f'^\s*URL:\s+(.*object={label}.*)$')
        for line in self._object_listing:
            m = object_re.fullmatch(line)
            if m and str(type) in m.group(1):
                return m.group(1)

    @property
    def test_env(self):
        """The environment variables expected by the mod_gnutls test Apache
        configuration to use this token."""
        return {
            'SOFTHSM2_CONF': str(Path(self.config).resolve()),
            'SOFTHSM_LIB': str(Path(self.softhsm_lib).resolve()),
            'P11_PIN': self.pin,
            'P11_CERT_URL': self.get_object_url(test_label, ObjectType.CERT),
            'P11_KEY_URL': self.get_object_url(test_label, ObjectType.PRIVATE)
        }

def find_softhsm_bin():
    """Find the SoftHSM Util binary to use.

    Returns the value selected by ./configure if available, otherwise
    searches the PATH for 'softhsm2-util'.

    """
    softhsm = os.environ.get('SOFTHSM')
    if softhsm and softhsm != 'no':
        return softhsm
    return shutil.which('softhsm2-util')

def find_softhsm_lib(libname=softhsm_libname, searchpath=softhsm_searchpath):
    """Get the path to the SoftHSM PKCS#11 module.

    Return SOFTHSM_LIB if set, otherwise search a list of directories
    for libsofthsm2.so.

    """
    lib = os.environ.get('SOFTHSM_LIB')
    if lib:
        return lib
    for p in searchpath:
        lib = p.joinpath(libname)
        if lib.is_file():
            return str(lib)

def tmp_softhsm_conf(db):
    """Create a temporary SOFTHSM2_CONF file, using an absolute path for
    the database.

    """
    with tempfile.NamedTemporaryFile(
            prefix='mod_gnutls_test-', suffix='.conf', delete=False) as conf:
        try:
            conf.write(b'objectstore.backend = file\n')
            conf.write(f'directories.tokendir = {Path(db).resolve()!s}\n'
                       .encode())
        except:
            Path(conf).unlink()
            raise
        return conf.name

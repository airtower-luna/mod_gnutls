#!/usr/bin/python3

# Copyright 2020 Krista Karppinen
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

"""OCSP specific generic code and classes for mod_gnutls tests"""

import re
import subprocess


class OCSPException(Exception):
    pass


class OCSPMessage:
    def __init__(self, fields, ignore_unknown=False):
        self.init_fields()
        for parse_name, value in fields.items():
            field_name = self.get_field_name(parse_name)
            if field_name is not None:
                self.fields[field_name].set_value(value)
            elif not ignore_unknown:
                raise OCSPException(f'Unknown field: {parse_name}')

        for field_name, field in self.fields.items():
            if field.is_mandatory() and not field.has_value():
                raise OCSPException(
                    f'Missing value for mandatory field: {field_name}')

    def init_fields(self):
        hex_pattern = re.compile(r'[0-9a-z]+')
        self.fields = {
            'issuer_name_hash': OCSPMessageField(
                'Issuer Name Hash', mandatory=True, value_pattern=hex_pattern),
            'issuer_key_hash': OCSPMessageField(
                'Issuer Key Hash', mandatory=True, value_pattern=hex_pattern),
            'serial_number': OCSPMessageField(
                'Serial Number', mandatory=True, value_pattern=hex_pattern),
            'nonce': OCSPMessageField(
                'Nonce', mandatory=False, value_pattern=hex_pattern),
        }

    def __repr__(self):
        return f'{self.get_message_type()}\n' + \
            '\n'.join([f'  {f}' for f in self.fields.values()])

    def get_field_name(self, parse_name):
        for key, field in self.fields.items():
            if field.get_parse_name() == parse_name:
                return key
        return None

    def get_field(self, field_name):
        if field_name not in self.fields:
            raise OCSPException(f'Unknown field: {field_name}')
        return self.fields[field_name]

    @classmethod
    def parse_ocsptool_output(cls, output):
        pattern = re.compile(r'\s*([a-zA-Z ]+): ([0-9a-f]+)')
        fields = {}
        for line in output.split('\n'):
            match = pattern.match(line)
            if match:
                fields[match.group(1)] = match.group(2)

        return cls(fields, ignore_unknown=True)


class OCSPMessageField:
    def __init__(self, parse_name, mandatory, value=None, value_pattern=None):
        self.parse_name = parse_name
        self.mandatory = mandatory
        self.value = value
        if type(value_pattern) is str:
            self.value_pattern = re.compile(value_pattern)
        else:
            self.value_pattern = value_pattern

    def get_parse_name(self):
        return self.parse_name

    def is_mandatory(self):
        return self.mandatory

    def has_value(self):
        return (self.value is not None)

    def get_value(self):
        if self.value is None:
            raise OCSPException('Field has no value')
        return self.value

    def set_value(self, new_value):
        if self.value_pattern and not self.value_pattern.fullmatch(new_value):
            raise OCSPException(f'Value does not match pattern: {new_value}')
        self.value = new_value

    def __repr__(self):
        m = '*' if self.mandatory else ''
        return f'{m}{self.parse_name}: {self.value}'


class OCSPRequest(OCSPMessage):
    @classmethod
    def get_message_type(cls):
        return 'OCSP Request'

    @classmethod
    def parse_str(cls, request_bytes):
        command = ['ocsptool', '--request-info']
        output = subprocess.check_output(command, input=request_bytes).decode()
        return cls.parse_ocsptool_output(output)


class OCSPResponse(OCSPMessage):
    @classmethod
    def get_message_type(cls):
        return 'OCSP Response'

    @classmethod
    def parse_file(cls, der_filename):
        command = ['ocsptool', '--response-info',
                   '--infile', der_filename]
        output = subprocess.check_output(command).decode()
        return cls.parse_ocsptool_output(output)

    def matches_request(self, request):
        if type(request) is not OCSPRequest:
            raise OCSPException(f'Expected OCSPRequest, got {type(request)}')

        matching_fields = [
            'issuer_name_hash', 'issuer_key_hash', 'serial_number']
        for field_name in matching_fields:
            if self.get_field(field_name).get_value() != \
                    request.get_field(field_name).get_value():
                return False
        return True

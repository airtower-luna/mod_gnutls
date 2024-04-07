#!/usr/bin/python3
#
# Mirror CGI script: Return the request body to the sender
#
# Copyright 2024 Fiona Klute
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.
import os
import sys

if os.environ['REQUEST_METHOD'] == 'POST':
    # mirror the incoming content type
    print('Status: 200 OK\n'
          f'Content-Type: {os.environ["CONTENT_TYPE"]}\n')
    for line in sys.stdin:
        print(line, end='')
else:
    print('Status: 405 Method Not Allowed\n'
          'Content-Type: text/plain\n\n'
          'Unsupported HTTP method.')

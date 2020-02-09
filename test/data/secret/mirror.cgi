#!/bin/bash
#
# Mirror CGI script: Return the request body to the sender
#
# Copyright 2020 Fiona Klute
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

case "${REQUEST_METHOD}" in
    ("POST")
	echo "Status: 200 OK"
	# mirror the incoming content type
	echo -e "Content-Type: ${CONTENT_TYPE}\n"
	# return the incoming data
	cat -
	;;
    (*)
	echo "Status: 405 Method Not Allowed"
	echo -e "Content-Type: text/plain\n"
	echo "Unsupported HTTP method."
	;;
esac

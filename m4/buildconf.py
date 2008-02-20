#!/usr/bin/env python
#
#  buildconf.py: Runs Autotools on a project.
#
#  Copyright 2004 Edward Rudd and Paul Querna
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import os
import sys
import popen2
from optparse import OptionParser

cmd = {}

def run_cmd(command, args=""):
	global cmd
	rp = popen2.Popen4("%s %s" % (cmd[command], args))
	sout = rp.fromchild.readlines()
	for line in sout:
		sys.stdout.write(line)
	rv = rp.wait()
	if rv != 0:
		print "Error: '%s %s' returned %d" % (cmd[command], args, rv)
		sys.exit(-1)

def select_cmd(command, list, args = "--version"):
	global cmd
	cmd[command] = None
	for x in list:
		# rv = os.spawnlp(os.P_WAIT, x, args)
		rp = popen2.Popen4("%s %s" % (x, args))
		rv = rp.wait()
		if rv == 0:
			cmd[command] = x
			break
	if cmd[command] == None:
		print "Errpr: Could not find suitable version for '%s', tried running: %s" % (command, list)
		sys.exit(-1)		

parser = OptionParser()

parser.add_option("--libtoolize", action="store_true", dest="libtoolize", default=False)
parser.add_option("--aclocal", action="store_true", dest="aclocal", default=False)
parser.add_option("--automake", action="store_true", dest="automake", default=False)
parser.add_option("--autoconf", action="store_true", dest="autoconf", default=False)
parser.add_option("--autoheader", action="store_true", dest="autoheader", default=False)

(options, args) = parser.parse_args()

if options.libtoolize:
	select_cmd("libtoolize", ['libtoolize14','glibtoolize','libtoolize']) 
if options.aclocal:
	select_cmd("aclocal", ['aclocal-1.9','aclocal-1.8','aclocal-1.7','aclocal-1.6','aclocal']) 
if options.autoheader:
	select_cmd("autoheader", ['autoheader259','autoheader257','autoheader']) 
if options.automake:
	select_cmd("automake", ['automake-1.9','automake-1.8','automake-1.7','automake-1.6','automake']) 
if options.autoconf:
	select_cmd("autoconf", ['autoconf259','autoconf257','autoconf']) 

if options.libtoolize:
	run_cmd("libtoolize", "--force --copy") 
if options.aclocal:
	run_cmd("aclocal", "-I m4") 
if options.autoheader:
	run_cmd("autoheader") 
if options.automake:
	run_cmd("automake", "--add-missing --copy --foreign") 
if options.autoconf:
	run_cmd("autoconf") 


#!/usr/bin/python3
import os
import re
import shutil
import subprocess

required_modules = {'logio', 'unixd', 'log_config'}

apache2 = os.environ.get('APACHE2')
if not apache2:
    apache2 = shutil.which('apache2')
if not apache2:
    apache2 = shutil.which('httpd')

result = subprocess.run([apache2, '-l'], check=True,
                        stdout=subprocess.PIPE, text=True)

built_in_modules = set()
mod_re = re.compile(r'^\s+mod_(\w+)\.c')
for line in result.stdout.splitlines():
    m = mod_re.match(line)
    if m:
        built_in_modules.add(m.group(1))

for mod in (required_modules - built_in_modules):
    print(f'LoadModule\t{mod}_module\t${{AP_LIBEXECDIR}}/mod_{mod}.so')

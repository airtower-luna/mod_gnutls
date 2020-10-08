#!/usr/bin/python3
import os
import re
import subprocess
from pathlib import Path

required_modules = {'logio', 'unixd', 'log_config'}

apache2 = os.environ['APACHE2']

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

# select mpm module, list is ordered by preference
mpm_choices = ['event', 'worker']
mod_dir = Path(os.environ['AP_LIBEXECDIR'])
for mpm in mpm_choices:
    mod = mod_dir.joinpath(f'mod_mpm_{mpm}.so')
    if mod.exists():
        print(f'LoadModule\tmpm_{mpm}_module\t{mod!s}')
        break

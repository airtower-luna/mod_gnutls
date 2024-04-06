import os
import asyncio
from pathlib import Path

srcdir = Path(os.environ['srcdir'])
testdir = srcdir / 'tests'


async def run_test(c, num, name):
    netns = srcdir / 'netns_py.bash'
    runtest = srcdir / 'runtest.py'
    s = await asyncio.create_subprocess_exec(
        str(netns), str(runtest), '--test-number', str(num),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    await s.wait()
    stdout, stderr = await s.communicate()
    with open(Path(f'{num:02}_{name.replace(" ", "_")}.log'), 'wb') as fh:
        fh.write(b'======= stdout =======\n\n')
        fh.write(stdout)
        fh.write(b'\n======= stderr =======\n\n')
        fh.write(stderr)

    if s.returncode == 0:
        return c, f'ok {c} - {name}'
    elif s.returncode == 77:
        return c, f'ok {c} - {name} # SKIP'
    else:
        return c, f'not ok {c} - {name}'


async def run(tests):
    print('TAP version 14')
    tasks = list()
    for c, (num, name) in enumerate(tests, start=1):
        tasks.append(run_test(c, num, name))
    # contrary to TAP specification the Meson runner requires results in order
    results = sorted(await asyncio.gather(*tasks), key=lambda r: r[0])
    for r in results:
        print(r[1])
    print(f'1..{c}')


if __name__ == '__main__':
    tests = map(
        lambda t: (int(t[0]), t[1].replace('_', ' ')),
        (
            t.name.split('_', maxsplit=1)
            for t in testdir.iterdir() if t.is_dir()
        ))
    asyncio.run(run(tests))

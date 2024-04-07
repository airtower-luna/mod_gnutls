import asyncio
import os
import shlex
import sys
from pathlib import Path

srcdir = Path(os.environ['srcdir'])
testdir = srcdir / 'tests'


async def runtest_namespace(*command):
    """Run the given runtest.py command in a namespace (via unshare),
    otherwise directly in a fresh Python interpreter instance.

    If a namespace is used, it will have an active loopback
    interface. Note that "unshare" is called twice: First to create
    network/IPC/user namespaces with root (so activating loopback
    works), and then again to create another user namespace so the
    test does not run as root even in the namespace (otherwise Apache
    will try to change user and fail).

    """
    if os.environ.get('USE_TEST_NAMESPACE'):
        unshare = os.environ['UNSHARE']
        c = [
            unshare, '--net', '--ipc', '-r',
            'sh', '-c',
            'export MGS_NETNS_ACTIVE=1; ip link set up lo; '
            f'exec {shlex.quote(unshare)} '
            f'--user {shlex.quote(sys.executable)} '
            f'-u {shlex.join(command)}']
    else:
        c = [sys.executable, '-u', *command]

    s = await asyncio.create_subprocess_exec(
        *c,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    await s.wait()
    return s


async def run_test(c, num, name):
    runtest = srcdir / 'runtest.py'
    valgrind_args = ()
    if os.environ.get('ENABLE_VALGRIND') == 'true':
        valgrind_args = (
            '--valgrind',
            '--valgrind-suppressions',
            str(srcdir / 'suppressions.valgrind'),
        )

    s = await runtest_namespace(
        str(runtest), *valgrind_args, '--test-number', str(num))
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

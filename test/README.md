# Unit Tests for Apache's mod_gnutls

Authors:
Daniel Kahn Gillmor <dkg@fifthhorseman.net>,
Fiona Klute <fiona.klute@gmx.de>

There are a lot of ways that a TLS-capable web server can go wrong.  I
want to at least test for some basic/common configurations.


## Running the tests

Run the tests, adjust the path according to where your build directory
is:

```bash
meson test -C build/ --verbose
```

The default configuration assumes that a loopback device is available,
and that `localhost` resolves to the IPv6 and IPv4 loopback
addresses. You can override the defaults by setting the `test-host`
and `test-ips` Meson build options, e.g. to unconditionally use IPv4
only:

```bash
$ meson setup -Dtest-host=localhost -Dtest-ips=127.0.0.1 build
```

Note that having less than two addresses (comma separated) in
`test-ips` will lead to some tests being skipped.


## Implementation

Each test is defined by a directory in `tests/`, which the test suite
uses to spin up an isolated Apache instance (or more, for tests that
need a proxy or OCSP responder) and try to connect to it with
`gnutls-cli` and make a simple HTTP request (or `curl`, for HTTP/2).

Test directories usually contain the following files:

* `apache.conf` -- Apache configuration to be used

* `test.yaml` -- Defines the client connection(s) including parameters
  for `gnutls-cli`, the request(s), and expected response(s). Please
  see the module documentation of [mgstest.tests](./mgstest/tests.py)
  for details, and [`sample_test.yaml`](./sample_test.yaml) and
  [`sample_fail.yaml`](./sample_fail.yaml) for examples.

* `backend.conf` [optional] -- Apache configuration for the proxy
  backend server, if any

* `ocsp.conf` [optional] -- Apache configuration for the OCSP
  responder, if any

* `fail.server` [optional] -- if this file exists, it means we expect
  the web server to fail to even start due to some serious
  configuration problem.

* `hooks.py` [optional] -- Defines hook functions that modify or
  override the default behavior of `runtest.py`. Please see the module
  documentation of [mgstest.hooks](./mgstest/hooks.py) for details.

The [`runtest.py`](./runtest.py) program is used to start the required
services send a request (or more) based on the files described
above.

By default (if the `unshare` command is available and has the
permissions required to create network and user namespaces), each test
case is run inside its own network namespace. This avoids address and
port conflicts with other tests as well has the host system. Otherwise
the tests use a lock file to prevent port conflicts between
themselves.


## Robustness and Tuning

Here are some things that you might want to tune about the tests based
on your expected setup:

* They need a functioning loopback device.

* They expect to have ports 9932 (`TEST_PORT` as defined in
  [`test/meson.build`](./meson.build)) through 9936 available for test
  services to bind to, and open for connections on the addresses
  listed in `test-ips`. Note that the OCSP server port is included in
  certificates, if you change it you must rebuild them or tests will
  fail.

* Depending on the compile time configuration of the Apache binary
  installed on your system you may need to load additional Apache
  modules. The recommended way to do this is to drop a configuration
  file into the `apache-conf/` directory. Patches to detect such
  situations and automatically configure the tests accordingly are
  welcome.

* If a machine is particularly slow or under heavy load, it's possible
  that tests fail for timing reasons. You can adjust
  `TEST_QUERY_TIMEOUT` (timeout for the HTTPS request in seconds) and
  the overall test run timeouts in [`test/meson.build`](./meson.build)
  if necessary.

The first two of these issues are avoided when the tests are isolated
using network namespaces, which is enabled if possible (see
"Implementation" above).

When running tests with `--verbose`, Meson shows the environment
variables defined for the test scripts. You can use this for running
tests manually, e.g. for debugging.

```bash
$ AP_LIBEXECDIR=/usr/lib/apache2/modules [many more...] ./test/runtest.py --test-number 0
```


## Testing with Valgrind memcheck

Enable Valgrind in `meson setup` or using `meson configure`:
`-Dvalgrind-test=true`

This will make the primary HTTPD instance in tests run under
Valgrind. While very slow that can be useful to catch memory leaks
early.

The [`suppressions.valgrind`](./suppressions.valgrind) file contains
some suppressions for known reported errors that are deemed not to be
mod\_gnutls issues. Note that the suppressions in that file are aimed
at Debian x86_64 (or similar) systems, you may need to adjust them on
other platforms. Currently the path of the suppressions file is fixed
in [`tap.py`](./tap.py).


## Coverage reports

You can generate coverage reports using the Meson coverage
infrastructure. Enable coverage recording in `meson setup` or using
`meson configure` with `-Db_coverage=true`, and run the tests. **Do
not use a profiling build for production!**

Then generate the coverage report with: `ninja -C build/ coverage-html`

The report will be in the build dir at
`meson-logs/coveragereport/index.html`.


## Adding a Test

Please add more tests!

The simplest way to add a test is (from the directory containing this
file):

```bash
$ ./newtest
```

This will prompt you for a simple name for the test, and copy a
starting set of files from `tests/00_basic`.

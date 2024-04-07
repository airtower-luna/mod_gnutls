gen_ocsp_index = executable(
  'gen_ocsp_index', 'gen_ocsp_index.c', 'cert_helper.c',
  dependencies: [gnutls])

python = import('python').find_installation(modules: ['yaml'])
testscripts = files(
  [
    'doctest-mgstest.py',
    'tap.py',
    'unittest-mgstest.py',
  ])
doctest = testscripts[0]
tap_py = testscripts[1]
unittest = testscripts[2]

subdir('apache-conf')
port = 9932

env = environment()
env.set('srcdir', meson.source_root() / 'test')
env.set('MESON_BUILD_ROOT', meson.build_root())
env.set('PWD', meson.build_root() / 'test')
env.set('TEST_HOST', get_option('test-host'))
env.set('TEST_IP', get_option('test-ips'), separator: ' ')
env.set('TEST_PORT', f'@port@')
env.set('TEST_HTTP_PORT', '@0@'.format(port + 1))
env.set('APACHE2', httpd.path())
env.set('AP_LIBEXECDIR', mod_dir)
env.set('USE_TEST_NAMESPACE', '1')
env.set('OCSP_PORT', '@0@'.format(port + 4))
env.set('OCSP_URI_TEMPLATE',
	'ocsp_uri = http://@0@:@1@/ocsp/'.format(
	  get_option('test-host'), port + 4))
env.set('BACKEND_HOST', get_option('test-host'))
env.set('BACKEND_PORT', '@0@'.format(port + 2))
if openssl.found()
  env.set('OPENSSL', openssl.path())
endif
env.set('PYTHON', python.path())
env.set('UNSHARE', 'unshare')
env.set('HTTP_CLI', 'curl')
if get_option('valgrind-test')
  env.set('ENABLE_VALGRIND', 'true')
  env.set('TEST_QUERY_TIMEOUT', '30')
endif

test_dirs = custom_target(
  'create directories used for tests',
  output: ['cache', 'logs', 'outputs'],
  input: [],
  command: ['mkdir', '-p', '@OUTPUT@'])

test_ca = files(['test_ca.mk'])[0]

test_pki = custom_target(
  'build test PKI',
  build_always_stale: true,
  output: ['authority', 'rogueca'],
  input: [
    test_ca,
    'authority/meow.test/template.in',
    'authority/subca/ocsp-responder/template.in',
    'authority/subca/server/template.in',
    'authority/subca/template.in',
    'authority/client/template.in',
    'authority/ocsp-responder/template.in',
    'authority/server/template.in',
    'authority/template.in',
    'rogueca/rogueclient/template.in',
    'rogueca/imposter/template.in',
    'rogueca/template.in',
  ],
  depends: [gen_ocsp_index],
  command: [
    'make', '--no-builtin-rules',
    '-C', '@OUTDIR@',
    '-f', meson.build_root() / '@INPUT0@',
    'authority/x509.pem',
    'authority/x509-chain.pem',
    'authority/client/x509.pem',
    'authority/meow.test/x509-chain.pem',
    'authority/meow.test/x509.pem',
    'authority/ocsp-responder/x509.pem',
    'authority/server/x509-chain.pem',
    'authority/server/x509.pem',
    'authority/server/crl.pem',
    'authority/server/softhsm2.db',
    'authority/subca/x509-chain.pem',
    'authority/subca/x509.pem',
    'authority/subca/ocsp-responder/x509.pem',
    'authority/subca/server/x509-chain.pem',
    'authority/subca/server/x509.pem',
    'rogueca/x509.pem',
    'rogueca/imposter/x509.pem',
    'rogueca/rogueclient/x509.pem',
    'authority/ocsp_index.txt',
    'authority/ocsp_index.txt.attr',
    'authority/subca/ocsp_index.txt',
    'authority/subca/ocsp_index.txt.attr',
  ],
  env: env)

test('integration', python, args: [tap_py],
     env: env,
     protocol: 'tap',
     workdir: meson.build_root() / 'test',
     depends: [test_pki, test_dirs, mod_gnutls, listen_conf, modules_conf])

test('doctest', doctest,
     env: env,
     depends: [test_pki, mod_gnutls])

test('unittest', unittest,
     env: env,
     depends: [test_pki, mod_gnutls])

if pandoc.found()
  test_doc = custom_target(
    'test-doc',
    output : 'README.html',
    input : [
      'README.md',
      doc_style],
    command : [
      pandoc, '--css', '@INPUT1@',
      '--toc', '--self-contained',
      '-f', 'markdown',
      '--metadata', 'title=mod_gnutls test system',
      '-o', '@OUTPUT@',
      '@INPUT0@'],
    install_tag: 'doc')
endif

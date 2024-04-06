sources = files([
    'gnutls_cache.c',
    'gnutls_config.c',
    'gnutls_hooks.c',
    'gnutls_io.c',
    'gnutls_ocsp.c',
    'gnutls_proxy.c',
    'gnutls_sni.c',
    'gnutls_util.c',
    'gnutls_watchdog.c',
    'mod_gnutls.c',
])
mod_gnutls = shared_module(
  'mod_gnutls', sources,
  include_directories: incdir,
  dependencies: [apr, apr_util, apache2, gnutls],
  name_prefix: '',
  install: true,
  install_dir: mod_dir)

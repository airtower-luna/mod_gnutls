project('mod_gnutls', 'c',
	version: '0.12.3',
	license: 'Apache-2.0',
	# enable when all CI jobs use Meson >= 1.1 (Trixie release)
	# license_files: 'LICENSE',
	default_options: [
	  'c_std=gnu11',
	  'warning_level=3',
	  'werror=true',
	])

conf_data = configuration_data()
conf_data.set('MOD_GNUTLS_VERSION', meson.project_version())
conf_data.set('PACKAGE_NAME', meson.project_name())
if get_option('gnutls-debug-log')
  conf_data.set('MOD_GNUTLS_DEBUG', 1)
else
  conf_data.set('MOD_GNUTLS_DEBUG', 0)
endif
add_project_arguments('-Wno-error=deprecated-declarations', language: 'c')
# unfortunately libapr has some of that in macros
if meson.get_compiler('c').get_id() == 'clang'
  add_project_arguments('-Wno-error=null-pointer-subtraction', language: 'c')
endif

apr = dependency('apr-1')
apr_util = dependency('apr-util-1')
gnutls = dependency('gnutls', version: '>=3.6.3')
apxs = find_program(get_option('apxs-bin'), required: true)
apache2 = declare_dependency(
  include_directories: [
  run_command(apxs, '-q', 'INCLUDEDIR', check: true).stdout().strip()])
mod_dir = run_command(apxs, '-q', 'LIBEXECDIR', check: true).stdout().strip()

pandoc = find_program('pandoc', required: false)
if pandoc.found()
  pandoc_version = run_command(
    pandoc, '--version', check: true, capture: true).stdout().split()[1]
  message('Found Pandoc version:', pandoc_version)
endif
httpd = find_program('apache2', 'httpd', dirs: ['/usr/sbin'], required: true)

incdir = include_directories('include')
subdir('include')
subdir('src')
subdir('doc')
subdir('test')

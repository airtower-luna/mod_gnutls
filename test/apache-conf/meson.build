listen_conf = custom_target(
  'create Listen directives for HTTPD',
  output: ['listen.conf'],
  input: ['listen-conf.py'],
  command: [python, '@INPUT@', '@OUTPUT@'],
  env: {'TEST_IP': ' '.join(get_option('test-ips'))})

modules_conf = custom_target(
  'load required modules into HTTPD',
  output: ['required-modules.conf'],
  input: ['required-modules.py'],
  capture: true,
  command: [python, '@INPUT@'],
  env: {
	 'APACHE2': httpd.path(),
	 'AP_LIBEXECDIR': mod_dir,
       })

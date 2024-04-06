pdflatex = find_program('pdflatex', required: false)
doc_style = files('style.css')[0]

if pandoc.found()
  doc_meta = configure_file(input: 'mod_gnutls_manual.yaml.in',
			    output: 'mod_gnutls_manual.yaml',
			    configuration : conf_data)

  man_doc = custom_target(
    'man doc',
    output : 'mod_gnutls.5',
    input : [
      'mod_gnutls.whatis',
      'mod_gnutls_manual.md',
      doc_meta],
    command : [
      pandoc, '--standalone', '-f', 'markdown',
      '-t', 'man',
      '-o', '@OUTPUT@',
      '@INPUT@'],
    install_tag: 'man',
    install: true,
    install_dir: join_paths(get_option('mandir'), 'man5'))

  html_doc = custom_target(
    'html doc',
    output : 'mod_gnutls_manual.html',
    input : [
      'mod_gnutls_manual.md',
      doc_meta,
      doc_style],
    command : [
      pandoc, '--css', '@INPUT2@',
      '--toc', '--self-contained',
      '-f', 'markdown',
      '-o', '@OUTPUT@',
      '@INPUT0@', '@INPUT1@'],
    install_tag: 'doc',
    install: true,
    install_dir: join_paths(get_option('datadir'), meson.project_name()))

  if pdflatex.found() and get_option('pdf-doc')
    pdf_doc = custom_target(
      'pdf doc',
    output : 'mod_gnutls_manual.pdf',
    input : [
      'mod_gnutls_manual.md',
      doc_meta],
    command : [
      pandoc, '--toc', '-f', 'markdown',
      '-o', '@OUTPUT@',
      '@INPUT@'],
    install_tag: 'doc',
    install: true,
    install_dir: join_paths(get_option('datadir'), meson.project_name()))
  endif
endif

doxygen = find_program('doxygen', required: false)
if doxygen.found()
  doxy_conf = configure_file(input: 'doxygen.conf.in',
			     output: 'doxygen.conf',
			     configuration : conf_data)
  api_doc = custom_target(
    'api-doc',
    output : ['api'],
    input : [
      doxy_conf,
      sources,
    ],
    command : [
      doxygen, '@INPUT0@'])
endif

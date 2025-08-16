# mod\_gnutls, Apache GnuTLS module

Homepage: https://github.com/airtower-luna/mod_gnutls

Mailing List: mod\_gnutls development <mod_gnutls-devel@lists.gnutls.org>

Lead Maintainer: Fiona Klute <fiona.klute@gmx.de>

Past maintainers and other contributors:

* Daniel Kahn Gillmor <dkg@fifthhorseman.net>
* Paul Querna <chip at force-elite.com>
* Nikos Mavrogiannopoulos <nmav at gnutls.org>
* Dash Shendy <neuromancer at dash.za.net>

## Prerequisites

* [GnuTLS](https://www.gnutls.org/) >= 3.6.3
* [Apache HTTPD](https://httpd.apache.org/) >= 2.4.17
* [Meson](https://mesonbuild.com/) >= 1.1
* GCC or Clang
* GNU Make
* Python 3 (for tests)
* [PyYAML](https://pyyaml.org/)
* [Pandoc](https://pandoc.org/) (for documentation, optional)
* pdflatex (for PDF documentation, optional)

## Installation

The build uses Meson, the example below puts the build in a directory
called `build/`.

```sh
meson setup build
meson compile -C build/
meson test -C build/
meson install -C build/
```

Then configure and restart Apache.

You may need to set `-Dtest-host` or `-Dtest-ips` in the setup stage
for the tests to work correctly if you have an unusual network setup,
please see [test/README.md](test/README.md) for details.

If Doxygen is available, you can build internal API documentation
using `meson compile -C build/ api-doc`. The documentation will be
placed in `build/doc/api/html/`.

## Configuration

Please see [doc/mod_gnutls_manual.md](doc/mod_gnutls_manual.md) for
more details. If Pandoc is available, HTML and PDF (requires pdflatex)
documentation will be built and installed as well.

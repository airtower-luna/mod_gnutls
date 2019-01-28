/**
 * Helper functions for certificate handling in the mod_gnutls test suite
 *
 * Copyright 2016 Fiona Klute
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You
 * may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* certificate buffer size in bytes when reading from STDIN */
#define CERT_BUF_SIZE 10240



/**
 * Read the file "filename" into "cert", plus a NULL byte at the
 * end. "filename" may be NULL, in that case input is read from
 * stdin. The size field of data is set accordingly. The data field is
 * allocated to the needed size, the caller must free it when no
 * longer needed.
 *
 * Returns zero on success, or an error code (errno after the failed
 * operation).
 */
size_t read_cert(const char* filename, gnutls_datum_t* cert)
{
    size_t bufsize = CERT_BUF_SIZE;
    int certfile = STDIN_FILENO;

    if (filename)
    {
        certfile = open(filename, O_RDONLY);
        if (certfile == -1)
        {
            error(0, errno, "opening certificate file %s failed",
                  filename);
            return errno;
        }
        struct stat filestat;
        if (fstat(certfile, &filestat))
        {
            error(0, errno, "fstat on certificate file failed");
            return errno;
        }
        /* buffer size with one extra byte for NULL termination */
        bufsize = filestat.st_size + 1;
    }

    cert->data = malloc(bufsize);
    if (!cert->data)
    {
        error(0, errno, "allocating certificate buffer failed");
        return errno;
    }

    size_t readbytes = 0;
    ssize_t r = 0;
    do
    {
        r = read(certfile, (cert->data + readbytes),
                 (bufsize - 1 - readbytes));
        if (r > 0)
            readbytes += r;
    }
    while (r > 0 || r == EINTR);

    /* report error, if any */
    if (r < 0)
    {
        error(0, errno, "reading certificate file failed");
        free(cert->data);
        cert->data = NULL;
        cert->size = 0;
        return errno;
    }

    /* add terminating NULL byte and trim buffer to required size */
    cert->data[readbytes] = '\0';
    cert->size = readbytes + 1;
    cert->data = realloc(cert->data, cert->size);
    if (!cert->data)
    {
        error(0, errno, "trimming certificate buffer failed");
        return errno;
    }

    /* close file if not reading from STDIN */
    if (filename)
        close(certfile);

    return GNUTLS_E_SUCCESS;
}



/**
 * Transform a DER encoded X.509 certificate to PEM using GnuTLS
 * import/export functions. The caller is responsible for releasing
 * the returned data structure when it is no longer needed. A return
 * value of NULL indicates an error.
 */
gnutls_datum_t* der_to_pem(const gnutls_datum_t* der)
{
    gnutls_x509_crt_t cert;
    gnutls_datum_t* pem = calloc(1, sizeof(gnutls_datum_t));

    gnutls_x509_crt_init(&cert);
    int rv = gnutls_x509_crt_import(cert, der, GNUTLS_X509_FMT_DER);

    if (rv == GNUTLS_E_SUCCESS)
    {
        size_t s = CERT_BUF_SIZE;
        pem->data = malloc(s);
        rv = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, pem->data, &s);
        pem->size = s;
    }

    if (rv != GNUTLS_E_SUCCESS)
    {
        fprintf(stderr, "certificate transformation failed: %s\n",
                gnutls_strerror(rv));
        free(pem->data);
        free(pem);
        pem = NULL;
    }

    gnutls_x509_crt_deinit(cert);
    return pem;
}

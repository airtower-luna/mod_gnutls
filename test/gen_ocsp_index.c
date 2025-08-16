/**
 * Tool to generate an index file for the OpenSSL OCSP responder
 *
 * NOTE: This is a tool for setting up the test environment. At the
 * moment, all certificates are marked as valid.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "cert_helper.h"



static int index_line(const char* filename)
{
    gnutls_datum_t rawcert;
    /* read_cert reports errors to STDERR, just return if there were any */
    if (read_cert(filename, &rawcert))
        return GNUTLS_E_FILE_ERROR;

    gnutls_x509_crt_t cert;
    gnutls_x509_crt_init(&cert);
    int ret = gnutls_x509_crt_import(cert, &rawcert, GNUTLS_X509_FMT_PEM);
    if (ret != GNUTLS_E_SUCCESS)
        goto cleanup;

    /* For each certificate the index file contains a line with the
     * tab separated fields declared below (in that order). */
    /* status, one of: V (valid), R (revoked), E (expired) */
    const char* flag = "V";
    /* expiration time (YYMMDDHHMMSSZ) */
    char expires[14];
    /* revocation time & optional reason (YYMMDDHHMMSSZ[,reason]), if
     * any */
    const char* revocation = "";
    /* serial number (hex), allocated when the length is known */
    char* serial = NULL;
    /* certificate filename, or "unknown" */
    const char* fname = "unknown";
    /* certificate DN */
    char dn[512];

    time_t etime = gnutls_x509_crt_get_expiration_time(cert);
    struct tm etmp;
    memset(&etmp, 0, sizeof(etmp));
    gmtime_r(&etime, &etmp);
    strftime(expires, sizeof(expires), "%y%m%d%H%M%SZ", &etmp);

    /* determine size of the serial number (in bytes) */
    size_t serial_size = 0;
    gnutls_x509_crt_get_serial(cert, NULL, &serial_size);
    /* allocate memory for serial number and its string representation */
    uint8_t* sno = calloc(serial_size, sizeof(uint8_t));
    serial = calloc(serial_size * 2 + 1, sizeof(char));
    /* actually get the serial */
    gnutls_x509_crt_get_serial(cert, sno, &serial_size);
    /* print serial into the buffer byte for byte */
    for (size_t i = 0; i < serial_size; i++)
        snprintf(serial + (2 * i), 3, "%.2X", sno[i]);
    /* free binary serial */
    free(sno);

    size_t dn_size = sizeof(dn);
    gnutls_x509_crt_get_dn(cert, dn, &dn_size);

    fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n",
            flag, expires, revocation, serial, fname, dn);

    /* free hex serial */
    free(serial);

cleanup:
    gnutls_x509_crt_deinit(cert);
    free(rawcert.data);
    return ret;
}



int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage:\t%s CERTIFICATE ...\n", argv[0]);
        return 1;
    }

    int ret = 0;
    for (int i = 1; i < argc; i++)
    {
        int rv = index_line(argv[i]);
        if (rv != GNUTLS_E_SUCCESS)
        {
            fprintf(stderr, "Error parsing %s: %s\n",
                    argv[i], gnutls_strerror(rv));
            ret = 1;
        }
    }
    return ret;
}

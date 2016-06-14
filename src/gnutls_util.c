/**
 *  Copyright 2016 Thomas Klute
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "gnutls_util.h"

#include <apr_strings.h>
#include <gnutls/gnutls.h>


const char* http_post_header(apr_pool_t *p, apr_uri_t *uri,
                             const char *content_type, const char *accept,
                             apr_size_t size)
{
    return apr_psprintf(p, "POST %s HTTP/1.0\r\n"
                        "Host: %s\r\n"
                        "Content-Type: %s\r\n"
                        "Accept: %s\r\n"
                        "Content-Length: %ld\r\n\r\n",
                        apr_uri_unparse(p, uri, APR_URI_UNP_OMITSITEPART),
                        uri->hostname, content_type,
                        accept != NULL ? accept : "*/*",
                        size);
}



apr_status_t sock_send_buf(apr_socket_t *sock, const char *buf,
                           const apr_size_t size)
{
    apr_status_t rv = APR_EINIT;
    apr_size_t len = 0;
    for (apr_size_t sent = 0; sent < size; sent += len)
    {
        len = size - sent;
        rv = apr_socket_send(sock, buf + sent, &len);
        /* API documentation for apr_socket_send(): "It is possible
         * for both bytes to be sent and an error to be returned."
         *
         * So break if there was an error, unless bytes were also
         * sent. In the latter case try to continue. */
        if (rv != APR_SUCCESS && len == 0)
            break;
    }
    return rv;
}



const char* read_line(apr_pool_t *p, apr_bucket_brigade *sockb,
                      apr_bucket_brigade *lineb)
{
    apr_brigade_cleanup(lineb);
    apr_status_t rv = apr_brigade_split_line(lineb, sockb,
                                             APR_BLOCK_READ,
                                             HTTP_HDR_LINE_MAX);
    if (rv != APR_SUCCESS)
        return NULL;

    char *line;
    apr_size_t len;
    rv = apr_brigade_pflatten(lineb, &line, &len, p);
    if (rv != APR_SUCCESS)
        return NULL;

    /* The last two characters on a correct header line are
     * "\r\n". Switch \r to \0 to chomp off the line break. */
    if (len >= 2 && line[len-1] == '\n' && line[len-2] == '\r')
    {
        line[len-2] = '\0';
        return line;
    }
    else
        return NULL;
}



apr_status_t datum_from_file(apr_pool_t *p, const char* filename,
                             gnutls_datum_t *datum)
{
    apr_status_t rv = APR_EINIT;
    apr_file_t *file;
    apr_finfo_t finfo;
    apr_size_t br = 0;
    rv = apr_file_open(&file, filename,
                       APR_READ | APR_BINARY, APR_OS_DEFAULT, p);
    if (rv != APR_SUCCESS)
        return rv;

    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, file);
    if (rv != APR_SUCCESS)
        return rv;

    datum->data = apr_palloc(p, finfo.size);
    rv = apr_file_read_full(file, datum->data, finfo.size, &br);
    if (rv != APR_SUCCESS)
        return rv;

    apr_file_close(file);

    /* safe integer type conversion */
    if (__builtin_add_overflow(br, 0, &datum->size))
        return APR_EINVAL;

    return rv;
}

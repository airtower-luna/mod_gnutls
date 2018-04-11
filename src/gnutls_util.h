/*
 *  Copyright 2016-2018 Fiona Klute
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

#include <apr_buckets.h>
#include <apr_lib.h>
#include <apr_network_io.h>
#include <apr_pools.h>
#include <apr_uri.h>
#include <gnutls/gnutls.h>
#include "mod_gnutls.h"

#ifndef __MOD_GNUTLS_UTIL_H__
#define __MOD_GNUTLS_UTIL_H__

/** maximum allowed length of one header line */
#define HTTP_HDR_LINE_MAX 1024

/**
 * Create an HTTP header to send a POST request with 'size' bytes of
 * data to 'uri'.
 */
const char* http_post_header(apr_pool_t *p, apr_uri_t *uri,
                             const char *content_type, const char *accept,
                             apr_size_t size)
    __attribute__((nonnull(1, 2, 3)));

/**
 * Try to transfer one header line from 'sockb' into 'lineb', then
 * return it from there. The line may be no more than
 * HTTP_HDR_LINE_MAX bytes long, including the terminating CRLF. CR is
 * replaced with \0 so the line can be processed as a string without
 * breaks. 'lineb' is flushed before reading the line. Returns either
 * a pointer to the line (allocated from 'p'), or NULL in case of an
 * error.
 */
const char* read_line(apr_pool_t *p, apr_bucket_brigade *sockb,
                      apr_bucket_brigade *lineb)
    __attribute__((nonnull));

/**
 * Send 'size' bytes from 'buf' over 'sock', using partial send
 * operations if necessary. Returns APR_SUCCESS or an APR error code
 * returned by apr_socket_send().
 */
apr_status_t sock_send_buf(apr_socket_t *sock, const char *buf,
                           const apr_size_t size)
    __attribute__((nonnull));

/**
 * Read a file into a gnutls_datum_t, allocate necessary memory from
 * the pool.
 */
apr_status_t datum_from_file(apr_pool_t *p, const char* filename,
                             gnutls_datum_t *datum)
    __attribute__((nonnull));

/**
 * Allocate the connection configuration structure if necessary, set
 * some defaults.
 */
mgs_handle_t *init_gnutls_ctxt(conn_rec *c);

#endif /* __MOD_GNUTLS_UTIL_H__ */

/*
 * Copyright 2020-2023 Fiona Klute
 *
 * Initial function definitions and documentation copied from
 * mod_gnutls.h.in under the same license, copyright notice:
 *
 * Copyright 2004-2005 Paul Querna
 * Copyright 2014 Nikos Mavrogiannopoulos
 * Copyright 2015-2020 Fiona Klute
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MOD_GNUTLS_IO_H__
#define __MOD_GNUTLS_IO_H__

#include <apr.h>
#include <apr_buckets.h>
#include <apr_errno.h>
#include <gnutls/gnutls.h>
#include <util_filter.h>

#include "mod_gnutls.h"

/**
 * mgs_filter_input will filter the input data by decrypting it using
 * GnuTLS and passes it cleartext. Implements `ap_in_filter_func()`.
 *
 * @param f     the filter info record
 * @param bb    the bucket brigade, where to store the result to
 * @param mode  the read mode (e.g. speculative, bytes, line)
 * @param block blocking or non-blocking read?
 * @param readbytes number of bytes to read (maximum)
 * @return result APR status code
 */
apr_status_t mgs_filter_input(ap_filter_t * f,
                              apr_bucket_brigade * bb,
                              ap_input_mode_t mode,
                              apr_read_type_e block,
                              apr_off_t readbytes);

/**
 * mgs_filter_output will encrypt the incoming bucket using GnuTLS and
 * passes it onto the next filter. Implements `ap_out_filter_func()`.
 *
 * @param f     the filter info record
 * @param bb    the bucket brigade, where to store the result to
 * @return result status
 */
apr_status_t mgs_filter_output(ap_filter_t * f,
                               apr_bucket_brigade * bb);

/**
 * Pull function for GnuTLS, called from GnuTLS to read encrypted
 * data from the client.
 *
 * Generic errnos used for `gnutls_transport_set_errno()`:
 * * `EAGAIN`: no data available at the moment, try again (maybe later)
 * * `EINTR`: read was interrupted, try again
 * * `EIO`: Unknown I/O error
 * * `ECONNABORTED`: Input BB does not exist (`NULL`)
 *
 * The reason we are not using `APR_TO_OS_ERROR` to map `apr_status_t`
 * to errnos is this warning [in the APR documentation][apr-warn]:
 *
 * > If the statcode was not created by apr_get_os_error or
 * > APR_FROM_OS_ERROR, the results are undefined.
 *
 * We cannot know if this applies to any error we might encounter.
 *
 * @param ptr GnuTLS session data pointer (the mod_gnutls context
 * structure)
 *
 * @param buffer buffer for the read data
 *
 * @param len maximum number of bytes to read (must fit into the
 * buffer)
 *
 * @return The number of bytes read (may be zero on EOF), or `-1` on
 * error. Note that some errors may warrant another try (see above).
 *
 * [apr-warn]: https://apr.apache.org/docs/apr/1.4/group__apr__errno.html#ga2385cae04b04afbdcb65f1a45c4d8506 "Apache Portable Runtime: Error Codes"
 */
ssize_t mgs_transport_read(gnutls_transport_ptr_t ptr,
                           void *buffer, size_t len);

/**
 * Push function for GnuTLS, used to send encrypted data to the client.
 *
 * `gnutls_transport_set_errno()` will be called with `EAGAIN` or
 * `EINTR` on recoverable errors, or `EIO` in case of unexpected
 * errors. See the description of mgs_transport_read() for details on
 * possible error codes.
 *
 * @param ptr GnuTLS session data pointer (the mod_gnutls context
 * structure)
 *
 * @param buffer buffer containing the data to send
 *
 * @param len length of the data
 * buffer)
 *
 * @return The number of written bytes, or `-1` on error. Note that
 * some errors may warrant another try (see above).
 */
ssize_t mgs_transport_write(gnutls_transport_ptr_t ptr,
                            const void *buffer, size_t len);

/**
 * mgs_transport_read is called from GnuTLS check if data is available
 * on the underlying transport.
 *
 * @param ptr     transport pointer, the mod_gnutls connection context
 * @param ms      maximum time to wait in milliseconds
 * @return GnuTLS requirement: "The callback should return 0 on
 *      timeout, a positive number if data can be received, and -1 on
 *      error."
 */
int mgs_transport_read_ready(gnutls_transport_ptr_t ptr,
                             unsigned int ms);

int mgs_reauth(mgs_handle_t * ctxt, request_rec *r);

#endif /* __MOD_GNUTLS_IO_H__ */

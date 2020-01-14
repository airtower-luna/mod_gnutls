/*
 * Copyright 2020 Fiona Klute
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
 * mgs_filter_input will filter the input data
 * by decrypting it using GnuTLS and passes it cleartext.
 *
 * @param f     the filter info record
 * @param bb    the bucket brigade, where to store the result to
 * @param mode  what shall we read?
 * @param block a block index we shall read from?
 * @return result status
 */
apr_status_t mgs_filter_input(ap_filter_t * f,
                              apr_bucket_brigade * bb,
                              ap_input_mode_t mode,
                              apr_read_type_e block,
                              apr_off_t readbytes);

/**
 * mgs_filter_output will filter the encrypt
 * the incoming bucket using GnuTLS and passes it onto the next filter.
 *
 * @param f     the filter info record
 * @param bb    the bucket brigade, where to store the result to
 * @return result status
 */
apr_status_t mgs_filter_output(ap_filter_t * f,
                               apr_bucket_brigade * bb);

/**
 * mgs_transport_read is called from GnuTLS to provide encrypted
 * data from the client.
 *
 * @param ptr     pointer to the filter context
 * @param buffer  place to put data
 * @param len     maximum size
 * @return size   length of the data stored in buffer
 */
ssize_t mgs_transport_read(gnutls_transport_ptr_t ptr,
                           void *buffer, size_t len);

/**
 * mgs_transport_write is called from GnuTLS to
 * write data to the client.
 *
 * @param ptr     pointer to the filter context
 * @param buffer  buffer to write to the client
 * @param len     size of the buffer
 * @return size   length of the data written
 */
ssize_t mgs_transport_write(gnutls_transport_ptr_t ptr,
                            const void *buffer, size_t len);

int mgs_rehandshake(mgs_handle_t * ctxt);

#endif /* __MOD_GNUTLS_IO_H__ */

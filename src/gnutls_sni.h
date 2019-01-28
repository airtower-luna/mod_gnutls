/*
 *  Copyright 2018 Fiona Klute
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

#ifndef __MOD_GNUTLS_SNI_H__
#define __MOD_GNUTLS_SNI_H__

int mgs_sni_ext_hook(void *ctx, unsigned tls_id,
                     const unsigned char *data, unsigned size);


/**
 * Wrapper for gnutls_server_name_get(): Retrieve SNI data from the
 * TLS session associated with the connection, store it in a string
 * allocated from the connection pool.
 *
 * Note that `ctxt->sni_name` is not automatically updated.
 *
 * @param ctxt the connection to read from
 *
 * @return the requested server name, or NULL.
 */
const char* mgs_server_name_get(mgs_handle_t *ctxt);

#endif /* __MOD_GNUTLS_SNI_H__ */

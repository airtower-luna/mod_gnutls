/*
 *  Copyright 2015-2018 Fiona Klute
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

#ifndef __MOD_GNUTLS_PROXY_H__
#define __MOD_GNUTLS_PROXY_H__

#include <apr_errno.h>
#include <apr_pools.h>
#include <httpd.h>

/** proxy modules may add a note with this key to the
 * connection->notes table for client connections to indicate the
 * server hostname */
#define PROXY_SNI_NOTE "proxy-request-hostname"

/** proxy modules may add a note with this key to the connection->notes
 * table for client connections to indicate supported protocols */
#define PROXY_ALPN_NOTE "proxy-request-alpn-protos"

apr_status_t load_proxy_x509_credentials(apr_pool_t *pconf,
                                         apr_pool_t *ptemp,
                                         server_rec *s)
    __attribute__((nonnull));

#endif /* __MOD_GNUTLS_PROXY_H__ */

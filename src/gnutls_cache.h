/**
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2014 Nikos Mavrogiannopoulos
 *  Copyright 2015-2016 Thomas Klute
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
 *
 */

#ifndef __MOD_GNUTLS_CACHE_H__
#define __MOD_GNUTLS_CACHE_H__

#include "mod_gnutls.h"
#include <httpd.h>

#define MGS_CACHE_MUTEX_NAME "gnutls-cache"

/**
 * Init the Cache after Configuration is done
 */
int mgs_cache_post_config(apr_pool_t *p, server_rec *s, mgs_srvconf_rec *sc);

/**
 * Init the Cache inside each Process
 */
int mgs_cache_child_init(apr_pool_t *p, server_rec *s, mgs_srvconf_rec *sc);

/**
 * Setup the Session Caching
 */
int mgs_cache_session_init(mgs_handle_t *ctxt);



/**
 * Convert a time_t into a Null Terminated String
 * @param t time_t time
 * @param str Location to store the Hex Encoded String
 * @param strsize The Maximum Length that can be stored in str
 */
char *mgs_time2sz(time_t t, char *str, int strsize);

/*
 * Generic object cache functions, used for OCSP caching
 */
typedef int (*cache_store_func)(server_rec *s, gnutls_datum_t key,
                                gnutls_datum_t data, apr_time_t expiry);
typedef gnutls_datum_t (*cache_fetch_func)(mgs_handle_t *ctxt,
                                           gnutls_datum_t key);
struct mgs_cache {
    cache_store_func store;
    cache_fetch_func fetch;
    /* Mutex for cache access (used only if the cache type is not
     * thread-safe) */
    apr_global_mutex_t *mutex;
};

#endif /** __MOD_GNUTLS_CACHE_H__ */

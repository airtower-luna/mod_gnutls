/*
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2014 Nikos Mavrogiannopoulos
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

/**
 * @file
 *
 * Generic object cache for mod_gnutls.
 */

#ifndef __MOD_GNUTLS_CACHE_H__
#define __MOD_GNUTLS_CACHE_H__

#include "mod_gnutls.h"
#include <httpd.h>

/** Name of the mod_gnutls cache access mutex, for use with Apache's
 * `Mutex` directive */
#define MGS_CACHE_MUTEX_NAME "gnutls-cache"

/**
 * Initialize the internal cache configuration structure. This
 * function is called after the configuration file(s) have been
 * parsed.
 *
 * @param p configuration memory pool
 * @param s default server of the Apache configuration, head of the
 * server list
 * @param sc mod_gnutls data associated with `s`
 */
int mgs_cache_post_config(apr_pool_t *p, server_rec *s, mgs_srvconf_rec *sc);

/**
 * (Re-)Initialize the cache in a child process after forking.
 *
 * @param p child memory pool provided by Apache
 * @param s default server of the Apache configuration, head of the
 * server list
 * @param sc mod_gnutls data associated with `s`
 */
int mgs_cache_child_init(apr_pool_t *p, server_rec *s, mgs_srvconf_rec *sc);

/**
 * Set up caching for the given TLS session.
 *
 * @param ctxt mod_gnutls session context
 *
 * @return 0
 */
int mgs_cache_session_init(mgs_handle_t *ctxt);



/**
 * Convert a `time_t` into a null terminated string in a format
 * compatible with OpenSSL's `ASN1_TIME_print()`.
 *
 * @param t time_t time
 * @param str Location to store the time string
 * @param strsize The maximum length that can be stored in `str`
 *
 * @return `str`
 */
char *mgs_time2sz(time_t t, char *str, int strsize);

/**
 * Generic store function for the mod_gnutls object cache.
 *
 * @param s server associated with the cache entry
 * @param key key for the cache entry
 * @param data data to be cached
 * @param expiry expiration time
 *
 * @return `-1` on error, `0` on success
 */
typedef int (*cache_store_func)(server_rec *s, gnutls_datum_t key,
                                gnutls_datum_t data, apr_time_t expiry);
/**
 * Generic fetch function for the mod_gnutls object cache.
 *
 * *Warning*: The `data` element of the returned `gnutls_datum_t` is
 * allocated using `gnutls_malloc()` for compatibility with the GnuTLS
 * session caching API, and must be released using `gnutls_free()`.
 *
 * @param server server context for the request
 *
 * @param key key for the cache entry to be fetched
 *
 * @param pool pool to allocate the response and other temporary
 * memory from
 *
 * @return the requested cache entry, or `{NULL, 0}`
 */
typedef gnutls_datum_t (*cache_fetch_func)(server_rec *server,
                                           gnutls_datum_t key,
                                           apr_pool_t *pool);
/**
 * Internal cache configuration structure
 */
struct mgs_cache {
    /** Store function for this cache */
    cache_store_func store;
    /** Fetch function for this cache */
    cache_fetch_func fetch;
    /** Mutex for cache access (used only if the cache type is not
     * thread-safe) */
    apr_global_mutex_t *mutex;
};

#endif /** __MOD_GNUTLS_CACHE_H__ */

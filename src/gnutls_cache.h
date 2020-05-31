/*
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2014 Nikos Mavrogiannopoulos
 *  Copyright 2015-2020 Fiona Klute
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
#include <ap_socache.h>

/** Name of the mod_gnutls cache access mutex, for use with Apache's
 * `Mutex` directive */
#define MGS_CACHE_MUTEX_NAME "gnutls-cache"

/** 8K is the maximum size accepted when receiving OCSP responses,
 * sessions cache entries should be much smaller. The buffer is
 * reallocated to actual size after fetching, so memory waste is
 * minimal and temporary. */
#define MGS_SESSION_FETCH_BUF_SIZE (8 * 1024)

/**
 * Configure a cache instance
 *
 * This function is supposed to be called during config and
 * initializes an mgs_cache_t by finding the named socache provider
 * and creating a cache instance with the given configuration. Note
 * that the socache instance is only created, not initialized, which
 * is supposed to happen during post_config.
 *
 * @param cache pointer to the mgs_cache_t, will be assigned only if
 * configuration succeeds
 *
 * @param server associated server for logging purposes
 *
 * @param type socache provider type
 *
 * @param config configuration string for the socache provider, may be
 * `NULL` if the provider accepts an empty configuration
 *
 * @param pconf configuration memory pool, used to store cache
 * configuration
 *
 * @param ptemp temporary memory pool
 */
const char *mgs_cache_inst_config(mgs_cache_t *cache, server_rec *server,
                                  const char* type, const char* config,
                                  apr_pool_t *pconf, apr_pool_t *ptemp);

/**
 * Initialize the internal cache configuration structure. This
 * function is called after the configuration file(s) have been
 * parsed.
 *
 * @param pconf configuration memory pool
 * @param ptemp temporary memory pool
 * @param s default server of the Apache configuration, head of the
 * server list
 * @param sc mod_gnutls data associated with `s`
 */
int mgs_cache_post_config(apr_pool_t *pconf, apr_pool_t *ptemp,
                          server_rec *s, mgs_srvconf_rec *sc);

/**
 * (Re-)Initialize the cache in a child process after forking.
 *
 * @param p child memory pool provided by Apache
 * @param s default server of the Apache configuration, head of the
 * server list
 * @param cache the cache to reinit
 * @param mutex_name name of the mutex associated with the cache for
 * logging purposes
 */
int mgs_cache_child_init(apr_pool_t *p, server_rec *server,
                         mgs_cache_t cache, const char *mutex_name);

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
 * Store function for the mod_gnutls object caches.
 *
 * @param cache the cache to store the entry in
 * @param s server associated with the cache entry
 * @param key key for the cache entry
 * @param data data to be cached
 * @param expiry expiration time
 *
 * @return `-1` on error, `0` on success
 */
int mgs_cache_store(mgs_cache_t cache, server_rec *server, gnutls_datum_t key,
                    gnutls_datum_t data, apr_time_t expiry);

/**
 * Fetch function for the mod_gnutls object caches.
 *
 * *Warning*: The `data` element of the returned `gnutls_datum_t` is
 * allocated using `gnutls_malloc()` for compatibility with the GnuTLS
 * session caching API, and must be released using `gnutls_free()`.
 *
 * @param cache the cache to fetch from
 *
 * @param server server context for the request
 *
 * @param key key for the cache entry to be fetched
 *
 * @param output pre-allocated buffer to write to and its size
 *
 * @param pool pool to allocate temporary memory from
 *
 * @return APR status or error value
 */
apr_status_t mgs_cache_fetch(mgs_cache_t cache, server_rec *server,
                             gnutls_datum_t key, gnutls_datum_t *output,
                             apr_pool_t *pool);

/**
 * Internal cache configuration structure
 */
struct mgs_cache {
    /** Socache provider to use for this cache */
    const ap_socache_provider_t *prov;
    /** The actual socache instance */
    ap_socache_instance_t *socache;
    /** Cache configuration string (as passed to the socache create
     * function, for logging) */
    const char *config;
    /** Mutex for cache access (used only if the cache type is not
     * thread-safe) */
    apr_global_mutex_t *mutex;
};

/**
 * Write cache status to a mod_status report
 *
 * @param cache the cache to report on
 *
 * @param header_title string to prefix the report with to distinguish
 * caches
 *
 * @param r status output is added to the response for this request
 *
 * @param flags request flags, used to toggle "short status" mode
 *
 * @return request status, currently always `OK`
 */
int mgs_cache_status(mgs_cache_t cache, const char *header_title,
                     request_rec *r, int flags);

#endif /** __MOD_GNUTLS_CACHE_H__ */

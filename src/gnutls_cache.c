/*
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
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
 * @file gnutls_cache.c
 *
 * This file contains the cache implementation used for session
 * caching and OCSP stapling. The `socache_*_session` functions
 * implement the GnuTLS session cache API using the configured cache,
 * using mgs_cache_store() and mgs_cache_fetch() as appropriate (see
 * gnutls_cache.h).
 */

#include "gnutls_cache.h"
#include "mod_gnutls.h"
#include "gnutls_config.h"

#include <ap_socache.h>
#include <apr_escape.h>
#include <util_mutex.h>

/** Default session cache timeout */
#define MGS_DEFAULT_CACHE_TIMEOUT 300

/** Session cache name */
#define MGS_SESSION_CACHE_NAME "gnutls_session"

/** Maximum length of the hex string representation of a GnuTLS
 * session ID: two characters per byte, plus one more for `\0` */
#if GNUTLS_VERSION_NUMBER >= 0x030400
#define GNUTLS_SESSION_ID_STRING_LEN ((GNUTLS_MAX_SESSION_ID_SIZE * 2) + 1)
#else
#define GNUTLS_SESSION_ID_STRING_LEN ((GNUTLS_MAX_SESSION_ID * 2) + 1)
#endif

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

/**
 * Turn a GnuTLS session ID into the key format we use for
 * caches. Name the Session ID as `server:port.SessionID` to disallow
 * resuming sessions on different servers.
 *
 * @return `0` on success, `-1` on failure
 */
static int mgs_session_id2dbm(conn_rec *c, unsigned char *id, int idlen,
                              gnutls_datum_t *dbmkey)
{
    char sz[GNUTLS_SESSION_ID_STRING_LEN];
    apr_status_t rv = apr_escape_hex(sz, id, idlen, 0, NULL);
    if (rv != APR_SUCCESS)
        return -1;

    char *newkey = apr_psprintf(c->pool, "%s:%d.%s",
                                c->base_server->server_hostname,
                                c->base_server->port, sz);
    dbmkey->size = strlen(newkey);
    /* signedness does not matter for arbitrary bits */
    dbmkey->data = (unsigned char*) newkey;
    return 0;
}

/** The OPENSSL_TIME_FORMAT macro and mgs_time2sz() serve to print
 * time in a format compatible with OpenSSL's `ASN1_TIME_print()`
 * function. */
#define OPENSSL_TIME_FORMAT "%b %d %k:%M:%S %Y %Z"

char *mgs_time2sz(time_t in_time, char *str, int strsize)
{
    apr_time_exp_t vtm;
    apr_size_t ret_size;
    apr_time_t t;


    apr_time_ansi_put(&t, in_time);
    apr_time_exp_gmt(&vtm, t);
    apr_strftime(str, &ret_size, strsize - 1, OPENSSL_TIME_FORMAT, &vtm);

    return str;
}



int mgs_cache_store(mgs_cache_t cache, server_rec *server,
                    gnutls_datum_t key, gnutls_datum_t data,
                    apr_time_t expiry)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(server->module_config, &gnutls_module);

    apr_pool_t *spool;
    apr_pool_create(&spool, NULL);

    if (cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_lock(cache->mutex);
    apr_status_t rv = cache->prov->store(cache->socache, server,
                                         key.data, key.size,
                                         expiry,
                                         data.data, data.size,
                                         spool);
    if (cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_unlock(cache->mutex);

    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, server,
                     "error storing in cache '%s:%s'",
                     cache->prov->name, sc->cache->config);
        apr_pool_destroy(spool);
        return -1;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, server,
                 "stored %u bytes of data (%u byte key) in cache '%s:%s'",
                 data.size, key.size,
                 cache->prov->name, sc->cache->config);
    apr_pool_destroy(spool);
    return 0;
}



/**
 * Store function for the GnuTLS session cache, see
 * gnutls_db_set_store_function().
 *
 * @param baton mgs_handle_t for the connection, as set via
 * gnutls_db_set_ptr()
 *
 * @param key object key to store
 *
 * @param data the object to store
 *
 * @return `0` in case of success, `-1` in case of failure
 */
static int socache_store_session(void *baton, gnutls_datum_t key,
                                 gnutls_datum_t data)
{
    mgs_handle_t *ctxt = baton;
    gnutls_datum_t dbmkey;

    if (mgs_session_id2dbm(ctxt->c, key.data, key.size, &dbmkey) < 0)
        return -1;

    apr_time_t expiry = apr_time_now() + ctxt->sc->cache_timeout;

    return mgs_cache_store(ctxt->sc->cache, ctxt->c->base_server,
                           dbmkey, data, expiry);
}



/** 8K is the maximum size accepted when receiving OCSP responses,
 * sessions cache entries should be much smaller. The buffer is
 * reallocated to actual size after fetching, so memory waste is
 * minimal and temporary. */
#define SOCACHE_FETCH_BUF_SIZE (8 * 1024)

gnutls_datum_t mgs_cache_fetch(mgs_cache_t cache, server_rec *server,
                               gnutls_datum_t key, apr_pool_t *pool)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(server->module_config, &gnutls_module);

    gnutls_datum_t data = {NULL, 0};
    data.data = gnutls_malloc(SOCACHE_FETCH_BUF_SIZE);
    if (data.data == NULL)
        return data;
    data.size = SOCACHE_FETCH_BUF_SIZE;

    apr_pool_t *spool;
    apr_pool_create(&spool, pool);

    if (cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_lock(cache->mutex);
    apr_status_t rv = cache->prov->retrieve(cache->socache, server,
                                            key.data, key.size,
                                            data.data, &data.size,
                                            spool);
    if (cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_unlock(cache->mutex);

    if (rv != APR_SUCCESS)
    {
        /* APR_NOTFOUND means there's no such object. */
        if (rv == APR_NOTFOUND)
            ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, server,
                         "requested entry not found in cache '%s:%s'.",
                         cache->prov->name, sc->cache->config);
        else
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, server,
                         "error fetching from cache '%s:%s'",
                         cache->prov->name, sc->cache->config);
        /* free unused buffer */
        gnutls_free(data.data);
        data.data = NULL;
        data.size = 0;
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, server,
                     "fetched %u bytes from cache '%s:%s'",
                     data.size, cache->prov->name, sc->cache->config);

        /* Realloc buffer to data.size. Data size must be less than or
         * equal to the initial buffer size, so this REALLY should not
         * fail. */
        data.data = gnutls_realloc(data.data, data.size);
        if (__builtin_expect(data.data == NULL, 0))
        {
            ap_log_error(APLOG_MARK, APLOG_CRIT, APR_ENOMEM, server,
                         "%s: Could not realloc fetch buffer to data size!",
                         __func__);
            data.size = 0;
        }
    }
    apr_pool_destroy(spool);

    return data;
}



/**
 * Fetch function for the GnuTLS session cache, see
 * gnutls_db_set_retrieve_function().
 *
 * *Warning*: The `data` element of the returned `gnutls_datum_t` is
 * allocated using `gnutls_malloc()` for compatibility with the GnuTLS
 * session caching API, and must be released using `gnutls_free()`.
 *
 * @param baton mgs_handle_t for the connection, as set via
 * gnutls_db_set_ptr()
 *
 * @param key object key to fetch
 *
 * @return the requested cache entry, or `{NULL, 0}`
 */
static gnutls_datum_t socache_fetch_session(void *baton, gnutls_datum_t key)
{
    gnutls_datum_t data = {NULL, 0};
    gnutls_datum_t dbmkey;
    mgs_handle_t *ctxt = baton;

    if (mgs_session_id2dbm(ctxt->c, key.data, key.size, &dbmkey) < 0)
        return data;

    return mgs_cache_fetch(ctxt->sc->cache, ctxt->c->base_server,
                           dbmkey, ctxt->c->pool);
}



/**
 * Remove function for the GnuTLS session cache, see
 * gnutls_db_set_remove_function().
 *
 * @param baton mgs_handle_t for the connection, as set via
 * gnutls_db_set_ptr()
 *
 * @param key object key to remove
 *
 * @return `0` in case of success, `-1` in case of failure
 */
static int socache_delete_session(void *baton, gnutls_datum_t key)
{
    gnutls_datum_t tmpkey;
    mgs_handle_t *ctxt = baton;

    if (mgs_session_id2dbm(ctxt->c, key.data, key.size, &tmpkey) < 0)
        return -1;

    if (ctxt->sc->cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_lock(ctxt->sc->cache->mutex);
    apr_status_t rv = ctxt->sc->cache->prov->remove(ctxt->sc->cache->socache,
                                                    ctxt->c->base_server,
                                                    key.data, key.size,
                                                    ctxt->c->pool);
    if (ctxt->sc->cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_unlock(ctxt->sc->cache->mutex);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     ctxt->c->base_server,
                     "error deleting from cache '%s:%s'",
                     ctxt->sc->cache->prov->name, ctxt->sc->cache->config);
        return -1;
    }
    return 0;
}



const char *mgs_cache_inst_config(mgs_cache_t *cache, server_rec *server,
                                  const char* type, const char* config,
                                  apr_pool_t *pconf, apr_pool_t *ptemp)
{
    /* allocate cache structure if needed */
    if (*cache == NULL)
    {
        *cache = apr_pcalloc(pconf, sizeof(struct mgs_cache));
        if (*cache == NULL)
            return "Could not allocate memory for cache configuration!";
    }
    mgs_cache_t c = *cache;

    /* Find the right socache provider */
    c->prov = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
                                 type,
                                 AP_SOCACHE_PROVIDER_VERSION);
    if (c->prov == NULL)
    {
        return apr_psprintf(ptemp,
                            "Could not find socache provider '%s', please "
                            "make sure that the provider name is valid and "
                            "the appropriate module is loaded (maybe "
                            "mod_socache_%s.so?).",
                            type, type);
    }

    /* shmcb works fine with NULL, but make sure there's a valid (if
     * empty) string for logging */
    if (config != NULL)
        c->config = apr_pstrdup(pconf, config);
    else
        c->config = "";

    /* Create and configure the cache instance. */
    const char *err = c->prov->create(&c->socache, c->config, ptemp, pconf);
    if (err != NULL)
    {
        return apr_psprintf(ptemp,
                            "Creating cache '%s:%s' failed: %s",
                            c->prov->name, c->config, err);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, server,
                 "%s: Socache '%s:%s' created.",
                 __func__, c->prov->name, c->config);

    return NULL;
}



/**
 * This function is supposed to be called during post_config to
 * initialize mutex and socache instance associated with an
 * mgs_cache_t.
 *
 * @param cache the mod_gnutls cache structure
 *
 * @param cache_name name for socache initialization
 *
 * @param mutex_name name to pass to ap_global_mutex_create(), must
 * have been registered during pre_config.
 *
 * @param server server for logging purposes
 *
 * @param pconf memory pool for server configuration
 */
static apr_status_t mgs_cache_inst_init(mgs_cache_t cache,
                                        const char *cache_name,
                                        const char *mutex_name,
                                        server_rec *server,
                                        apr_pool_t *pconf)
{
    apr_status_t rv = APR_SUCCESS;

    if (cache->mutex == NULL)
    {
        rv = ap_global_mutex_create(&cache->mutex, NULL,
                                    mutex_name,
                                    NULL, server, pconf, 0);
        ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, server,
                     "%s: create mutex", __func__);
        if (rv != APR_SUCCESS)
            return rv;
    }

    rv = cache->prov->init(cache->socache, cache_name, NULL, server, pconf);
    if (rv != APR_SUCCESS)
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, server,
                     "Initializing cache '%s:%s' failed!",
                     cache->prov->name, cache->config);
    else
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, server,
                     "%s: socache '%s:%s' initialized.", __func__,
                     cache->prov->name, cache->config);
    return rv;
}



static apr_status_t cleanup_socache(void *data)
{
    server_rec *s = data;
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                 "Cleaning up socache '%s:%s'",
                 sc->cache->prov->name, sc->cache->config);
    sc->cache->prov->destroy(sc->cache->socache, s);
    return APR_SUCCESS;
}



int mgs_cache_post_config(apr_pool_t *pconf,
                          apr_pool_t *ptemp __attribute__((unused)),
                          server_rec *s, mgs_srvconf_rec *sc)
{
    apr_status_t rv = APR_SUCCESS;
    /* GnuTLSCache was never explicitly set or is disabled: */
    if (sc->cache_enable == GNUTLS_ENABLED_UNSET
        || sc->cache_enable == GNUTLS_ENABLED_FALSE)
    {
        sc->cache_enable = GNUTLS_ENABLED_FALSE;
        /* Cache disabled, done. */
        return APR_SUCCESS;
    }
    /* if GnuTLSCacheTimeout was never explicitly set: */
    if (sc->cache_timeout == MGS_TIMEOUT_UNSET)
        sc->cache_timeout = apr_time_from_sec(MGS_DEFAULT_CACHE_TIMEOUT);

    rv = mgs_cache_inst_init(sc->cache, MGS_SESSION_CACHE_NAME,
                             MGS_CACHE_MUTEX_NAME, s, pconf);
    if (rv != APR_SUCCESS)
        return HTTP_INSUFFICIENT_STORAGE;

    apr_pool_pre_cleanup_register(pconf, s, cleanup_socache);

    return APR_SUCCESS;
}

int mgs_cache_child_init(apr_pool_t * p,
                         server_rec * s,
                         mgs_srvconf_rec * sc)
{
    /* reinit cache mutex */
    const char *lockfile = apr_global_mutex_lockfile(sc->cache->mutex);
    apr_status_t rv = apr_global_mutex_child_init(&sc->cache->mutex,
                                                  lockfile, p);
    if (rv != APR_SUCCESS)
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Failed to reinit mutex '%s'", MGS_CACHE_MUTEX_NAME);

    return 0;
}

int mgs_cache_session_init(mgs_handle_t * ctxt)
{
    if (ctxt->sc->cache_enable)
    {
        gnutls_db_set_retrieve_function(ctxt->session,
                                        socache_fetch_session);
        gnutls_db_set_remove_function(ctxt->session,
                                      socache_delete_session);
        gnutls_db_set_store_function(ctxt->session,
                                     socache_store_session);
        gnutls_db_set_ptr(ctxt->session, ctxt);
    }
    return 0;
}

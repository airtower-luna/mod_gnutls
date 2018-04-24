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
 * The signatures of the `(dbm|mc)_cache_...()` functions may be a bit
 * confusing: "store" and "expire" take a server_rec, "fetch" an
 * mgs_handle_t, and "delete" the `void*` required for a
 * `gnutls_db_remove_func`. The first two have matching `..._session`
 * functions to fit their respective GnuTLS session cache signatures.
 *
 * This is because "store", "expire" (dbm only), and "fetch" are also
 * needed for the OCSP cache. Their `..._session` variants have been
 * created to take care of the session cache specific parts, mainly
 * calculating the DB key from the session ID. They have to match the
 * appropriate GnuTLS DB function signatures.
 *
 * Additionally, there are the `mc_cache_(store|fetch)_generic()`
 * functions. They exist because memcached requires string keys while
 * DBM accepts binary keys, and provide wrappers to turn binary keys
 * into hex strings with a `mod_gnutls:` prefix.
 *
 * To update cached OCSP responses independent of client connections,
 * "store" and "expire" have to work without a connection context. On
 * the other hand "fetch" does not need to do that, because cached
 * OCSP responses will be retrieved for use in client connections.
 */

#include "gnutls_cache.h"
#include "mod_gnutls.h"
#include "gnutls_config.h"

#include <ap_socache.h>
#include <apr_escape.h>
#include <util_mutex.h>

/** Default session cache timeout */
#define MGS_DEFAULT_CACHE_TIMEOUT 300

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
 * Turn a GnuTLS session ID into the key format we use with DBM
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



static int socache_store(server_rec *server, gnutls_datum_t key,
                         gnutls_datum_t data, apr_time_t expiry)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(server->module_config, &gnutls_module);

    apr_pool_t *spool;
    apr_pool_create(&spool, NULL);

    if (sc->cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_lock(sc->cache->mutex);
    apr_status_t rv = sc->cache->prov->store(sc->cache->socache, server,
                                             key.data, key.size,
                                             expiry,
                                             data.data, data.size,
                                             spool);
    if (sc->cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_unlock(sc->cache->mutex);

    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, server,
                     "error storing in cache '%s:%s'",
                     sc->cache->prov->name, sc->cache_config);
        apr_pool_destroy(spool);
        return -1;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, server,
                 "stored %u bytes of data (%u byte key) in cache '%s:%s'",
                 data.size, key.size,
                 sc->cache->prov->name, sc->cache_config);
    apr_pool_destroy(spool);
    return 0;
}



static int socache_store_session(void *baton, gnutls_datum_t key,
                                 gnutls_datum_t data)
{
    mgs_handle_t *ctxt = baton;
    gnutls_datum_t dbmkey;

    if (mgs_session_id2dbm(ctxt->c, key.data, key.size, &dbmkey) < 0)
        return -1;

    apr_time_t expiry = apr_time_now() + ctxt->sc->cache_timeout;

    return socache_store(ctxt->c->base_server, dbmkey, data, expiry);
}



// 4K should be enough for OCSP responses and sessions alike
#define SOCACHE_FETCH_BUF_SIZE 4096
static gnutls_datum_t socache_fetch(server_rec *server, gnutls_datum_t key,
                                    apr_pool_t *pool)
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

    if (sc->cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_lock(sc->cache->mutex);
    apr_status_t rv = sc->cache->prov->retrieve(sc->cache->socache, server,
                                                key.data, key.size,
                                                data.data, &data.size,
                                                spool);
    if (sc->cache->prov->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        apr_global_mutex_unlock(sc->cache->mutex);

    if (rv != APR_SUCCESS)
    {
        /* APR_NOTFOUND means there's no such object. */
        if (rv == APR_NOTFOUND)
            ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, server,
                         "requested entry not found in cache '%s:%s'.",
                         sc->cache->prov->name, sc->cache_config);
        else
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, server,
                         "error fetching from cache '%s:%s'",
                         sc->cache->prov->name, sc->cache_config);
        /* free unused buffer */
        gnutls_free(data.data);
        data.data = NULL;
        data.size = 0;
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, server,
                     "fetched %u bytes from cache '%s:%s'",
                     data.size, sc->cache->prov->name, sc->cache_config);
    }
    apr_pool_destroy(spool);

    return data;
}

static gnutls_datum_t socache_fetch_session(void *baton, gnutls_datum_t key)
{
    gnutls_datum_t data = {NULL, 0};
    gnutls_datum_t dbmkey;
    mgs_handle_t *ctxt = baton;

    if (mgs_session_id2dbm(ctxt->c, key.data, key.size, &dbmkey) < 0)
        return data;

    return socache_fetch(ctxt->c->base_server, dbmkey, ctxt->c->pool);
}



static int socache_delete(void *baton, gnutls_datum_t key)
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
                     ctxt->sc->cache->prov->name, ctxt->sc->cache_config);
        return -1;
    }
    return 0;
}



static apr_status_t cleanup_socache(void *data)
{
    server_rec *s = data;
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                 "Cleaning up socache '%s:%s'",
                 sc->cache->prov->name, sc->cache_config);
    sc->cache->prov->destroy(sc->cache->socache, s);
    return APR_SUCCESS;
}



int mgs_cache_post_config(apr_pool_t *pconf, apr_pool_t *ptemp,
                          server_rec *s, mgs_srvconf_rec *sc)
{
    apr_status_t rv = APR_SUCCESS;
    /* if GnuTLSCache was never explicitly set: */
    if (sc->cache_type == mgs_cache_unset || sc->cache_type == mgs_cache_none)
    {
        sc->cache_type = mgs_cache_none;
        /* Cache disabled, done. */
        return APR_SUCCESS;
    }
    /* if GnuTLSCacheTimeout was never explicitly set: */
    if (sc->cache_timeout == MGS_TIMEOUT_UNSET)
        sc->cache_timeout = apr_time_from_sec(MGS_DEFAULT_CACHE_TIMEOUT);

    /* initialize mutex only once */
    if (sc->cache == NULL)
    {
        sc->cache = apr_palloc(pconf, sizeof(struct mgs_cache));
        rv = ap_global_mutex_create(&sc->cache->mutex, NULL,
                                    MGS_CACHE_MUTEX_NAME,
                                    NULL, s, pconf, 0);
        if (rv != APR_SUCCESS)
            return rv;
    }

    char *pname = NULL;

    if (sc->cache_type == mgs_cache_dbm || sc->cache_type == mgs_cache_gdbm)
        pname = "dbm";
    else if (sc->cache_type == mgs_cache_memcache)
        pname = "memcache";
    else if (sc->cache_type == mgs_cache_shmcb)
        pname = "shmcb";

    sc->cache->store = socache_store;
    sc->cache->fetch = socache_fetch;

    /* Find the right socache provider */
    sc->cache->prov = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
                                         pname,
                                         AP_SOCACHE_PROVIDER_VERSION);
    if (sc->cache->prov)
    {
        /* Cache found; create it, passing anything beyond the colon. */
        const char *err = sc->cache->prov->create(&sc->cache->socache,
                                                  sc->cache_config,
                                                  ptemp, pconf);
        if (err != NULL)
        {
            ap_log_error(APLOG_MARK, APLOG_EMERG, APR_EGENERAL, s,
                         "Creating cache '%s:%s' failed: %s",
                         pname, sc->cache_config, err);
            return HTTP_INSUFFICIENT_STORAGE;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                     "%s: Socache '%s' created.", __func__, pname);

        // TODO: provide hints
        rv = sc->cache->prov->init(sc->cache->socache,
                                   "mod_gnutls-session", NULL, s, pconf);
        if (rv != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                         "Initializing cache '%s:%s' failed!",
                         pname, sc->cache_config);
            return HTTP_INSUFFICIENT_STORAGE;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                     "%s: socache '%s:%s' created.", __func__,
                     pname, sc->cache_config);
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, APR_EGENERAL, s,
                     "Could not find socache provider '%s', please make sure "
                     "that the provider name is valid and the "
                     "appropriate mod_socache submodule is loaded.", pname);
        return HTTP_NOT_FOUND;
    }

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

#include <assert.h>

int mgs_cache_session_init(mgs_handle_t * ctxt)
{
    if (ctxt->sc->cache_type != mgs_cache_none)
    {
        gnutls_db_set_retrieve_function(ctxt->session,
                                        socache_fetch_session);
        gnutls_db_set_remove_function(ctxt->session,
                                      socache_delete);
        gnutls_db_set_store_function(ctxt->session,
                                     socache_store_session);
        gnutls_db_set_ptr(ctxt->session, ctxt);
    }
    return 0;
}

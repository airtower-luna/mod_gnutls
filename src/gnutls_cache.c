/**
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
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

/***
 * The signatures of the (dbm|mc)_cache_...() functions may be a bit
 * confusing: "store" and "expire" take a server_rec, "fetch" an
 * mgs_handle_t, and "delete" the void* required for a
 * gnutls_db_remove_func. The first two have matching ..._session
 * functions to fit their respective GnuTLS session cache signatures.
 *
 * This is because "store", "expire" (dbm only), and "fetch" are also
 * needed for the OCSP cache. Their ..._session variants have been
 * created to take care of the session cache specific parts, mainly
 * calculating the DB key from the session ID. They have to match the
 * appropriate GnuTLS DB function signatures.
 *
 * Additionally, there are the mc_cache_(store|fetch)_generic()
 * functions. They exist because memcached requires string keys while
 * DBM accepts binary keys, and provide wrappers to turn binary keys
 * into hex strings with a "mod_gnutls:" prefix.
 *
 * To update cached OCSP responses independent of client connections,
 * "store" and "expire" have to work without a connection context. On
 * the other hand "fetch" does not need to do that, because cached
 * OCSP responses will be retrieved for use in client connections.
 ***/

#include "gnutls_cache.h"
#include "mod_gnutls.h"

#if HAVE_APR_MEMCACHE
#include "apr_memcache.h"
#endif

#include "apr_dbm.h"
#include <apr_escape.h>

#include "ap_mpm.h"
#include <util_mutex.h>

#include <unistd.h>
#include <sys/types.h>

#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
#include "unixd.h"
#endif

/* default cache timeout */
#define MGS_DEFAULT_CACHE_TIMEOUT 300

/* it seems the default has some strange errors. Use SDBM
 */
#define MC_TAG "mod_gnutls:"
/* two characters per byte, plus one more for '\0' */
#define GNUTLS_SESSION_ID_STRING_LEN ((GNUTLS_MAX_SESSION_ID_SIZE * 2) + 1)

#if MODULE_MAGIC_NUMBER_MAJOR < 20081201
#define ap_unixd_config unixd_config
#endif

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

/* Name the Session ID as:
 * server:port.SessionID
 * to disallow resuming sessions on different servers
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

#define CTIME "%b %d %k:%M:%S %Y %Z"

char *mgs_time2sz(time_t in_time, char *str, int strsize) {
    apr_time_exp_t vtm;
    apr_size_t ret_size;
    apr_time_t t;


    apr_time_ansi_put(&t, in_time);
    apr_time_exp_gmt(&vtm, t);
    apr_strftime(str, &ret_size, strsize - 1, CTIME, &vtm);

    return str;
}

#if HAVE_APR_MEMCACHE

/* Name the Session ID as:
 * server:port.SessionID
 * to disallow resuming sessions on different servers
 */
static char *mgs_session_id2mc(conn_rec * c, unsigned char *id, int idlen)
{
    char sz[GNUTLS_SESSION_ID_STRING_LEN];
    apr_status_t rv = apr_escape_hex(sz, id, idlen, 0, NULL);
    if (rv != APR_SUCCESS)
        return NULL;

    return apr_psprintf(c->pool, MC_TAG "%s:%d.%s",
            c->base_server->server_hostname,
            c->base_server->port, sz);
}

/**
 * GnuTLS Session Cache using libmemcached
 *
 */

/* The underlying apr_memcache system is thread safe... woohoo */
static apr_memcache_t *mc;

static int mc_cache_child_init(apr_pool_t * p, server_rec * s,
        mgs_srvconf_rec * sc) {
    apr_status_t rv = APR_SUCCESS;
    int thread_limit = 0;
    int nservers = 0;
    char *cache_config;
    char *split;
    char *tok;

    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);

    /* Find all the servers in the first run to get a total count */
    cache_config = apr_pstrdup(p, sc->cache_config);
    split = apr_strtok(cache_config, " ", &tok);
    while (split) {
        nservers++;
        split = apr_strtok(NULL, " ", &tok);
    }

    rv = apr_memcache_create(p, nservers, 0, &mc);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                "[gnutls_cache] Failed to create Memcache Object of '%d' size.",
                nservers);
        return rv;
    }

    /* Now add each server to the memcache */
    cache_config = apr_pstrdup(p, sc->cache_config);
    split = apr_strtok(cache_config, " ", &tok);
    while (split) {
        apr_memcache_server_t *st;
        char *host_str;
        char *scope_id;
        apr_port_t port;

        rv = apr_parse_addr_port(&host_str, &scope_id, &port,
                split, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                    "[gnutls_cache] Failed to Parse Server: '%s'",
                    split);
            return rv;
        }

        if (host_str == NULL) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                    "[gnutls_cache] Failed to Parse Server, "
                    "no hostname specified: '%s'", split);
            return rv;
        }

        if (port == 0) {
            port = 11211; /* default port */
        }

        /* Should Max Conns be (thread_limit / nservers) ? */
        rv = apr_memcache_server_create(p,
                host_str, port,
                0,
                1, thread_limit, 600, &st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                    "[gnutls_cache] Failed to Create Server: %s:%d",
                    host_str, port);
            return rv;
        }

        rv = apr_memcache_add_server(mc, st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                    "[gnutls_cache] Failed to Add Server: %s:%d",
                    host_str, port);
            return rv;
        }

        split = apr_strtok(NULL, " ", &tok);
    }
    return rv;
}

static int mc_cache_store(server_rec *s, const char *key,
                          gnutls_datum_t data, apr_uint32_t timeout)
{
    apr_status_t rv = apr_memcache_set(mc, key, (char *) data.data,
                                       data.size, timeout, 0);

    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "[gnutls_cache] error setting key '%s' "
                     "with %d bytes of data", key, data.size);
        return -1;
    }

    return 0;
}

static int mc_cache_store_generic(server_rec *s, gnutls_datum_t key,
                                  gnutls_datum_t data, apr_time_t expiry)
{
    apr_uint32_t timeout = apr_time_sec(expiry - apr_time_now());

    apr_pool_t *p;
    apr_pool_create(&p, NULL);

    const char *hex = apr_pescape_hex(p, key.data, key.size, 1);
    if (hex == NULL)
    {
        apr_pool_destroy(p);
        return -1;
    }

    const char *strkey = apr_psprintf(p, MC_TAG "%s", hex);

    int ret = mc_cache_store(s, strkey, data, timeout);

    apr_pool_destroy(p);
    return ret;
}

static int mc_cache_store_session(void *baton, gnutls_datum_t key,
                                  gnutls_datum_t data)
{
    mgs_handle_t *ctxt = baton;

    const char *strkey = mgs_session_id2mc(ctxt->c, key.data, key.size);
    if (!strkey)
        return -1;

    apr_uint32_t timeout = apr_time_sec(ctxt->sc->cache_timeout);

    return mc_cache_store(ctxt->c->base_server, strkey, data, timeout);
}

static gnutls_datum_t mc_cache_fetch(conn_rec *c, const char *key)
{
    apr_status_t rv = APR_SUCCESS;
    char *value;
    apr_size_t value_len;
    gnutls_datum_t data = {NULL, 0};

    rv = apr_memcache_getp(mc, c->pool, key, &value, &value_len, NULL);

    if (rv != APR_SUCCESS)
    {
#if MOD_GNUTLS_DEBUG
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c,
                      "[gnutls_cache] error fetching key '%s' ",
                      key);
#endif
        return data;
    }

    /* TODO: Eliminate this memcpy. gnutls-- */
    data.data = gnutls_malloc(value_len);
    if (data.data == NULL)
        return data;

    data.size = value_len;
    memcpy(data.data, value, value_len);

    return data;
}

static gnutls_datum_t mc_cache_fetch_generic(mgs_handle_t *ctxt,
                                             gnutls_datum_t key)
{
    gnutls_datum_t data = {NULL, 0};
    const char *hex = apr_pescape_hex(ctxt->c->pool, key.data, key.size, 1);
    if (hex == NULL)
        return data;

    const char *strkey = apr_psprintf(ctxt->c->pool, MC_TAG "%s", hex);
    return mc_cache_fetch(ctxt->c, strkey);
}

static gnutls_datum_t mc_cache_fetch_session(void *baton, gnutls_datum_t key)
{
    mgs_handle_t *ctxt = baton;
    gnutls_datum_t data = {NULL, 0};

    const char *strkey = mgs_session_id2mc(ctxt->c, key.data, key.size);
    if (!strkey)
        return data;

    return mc_cache_fetch(ctxt->c, strkey);
}

static int mc_cache_delete(void *baton, gnutls_datum_t key) {
    apr_status_t rv = APR_SUCCESS;
    mgs_handle_t *ctxt = baton;
    char *strkey = NULL;

    strkey = mgs_session_id2mc(ctxt->c, key.data, key.size);
    if (!strkey)
        return -1;

    rv = apr_memcache_delete(mc, strkey, 0);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv,
                ctxt->c->base_server,
                "[gnutls_cache] error deleting key '%s' ",
                strkey);
        return -1;
    }

    return 0;
}

#endif	/* have_apr_memcache */

static const char *db_type(mgs_srvconf_rec * sc) {
    if (sc->cache_type == mgs_cache_gdbm)
        return "gdbm";
    else
        return "db";
}

#define SSL_DBM_FILE_MODE ( APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD )

static void dbm_cache_expire(server_rec *s)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    apr_status_t rv;
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    apr_time_t dtime;
    apr_pool_t *spool;
    int total, deleted;

    apr_time_t now = apr_time_now();

    if (now - sc->last_cache_check < (sc->cache_timeout) / 2)
        return;

    sc->last_cache_check = now;

    apr_pool_create(&spool, NULL);

    total = 0;
    deleted = 0;

    apr_global_mutex_lock(sc->cache->mutex);

    rv = apr_dbm_open_ex(&dbm, db_type(sc),
            sc->cache_config, APR_DBM_RWCREATE,
            SSL_DBM_FILE_MODE, spool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv, s,
                "[gnutls_cache] error opening cache '%s'",
                sc->cache_config);
        apr_global_mutex_unlock(sc->cache->mutex);
        apr_pool_destroy(spool);
        return;
    }

    apr_dbm_firstkey(dbm, &dbmkey);
    while (dbmkey.dptr != NULL) {
        apr_dbm_fetch(dbm, dbmkey, &dbmval);
        if (dbmval.dptr != NULL
                && dbmval.dsize >= sizeof (apr_time_t)) {
            memcpy(&dtime, dbmval.dptr, sizeof (apr_time_t));

            if (now >= dtime) {
                apr_dbm_delete(dbm, dbmkey);
                deleted++;
            }
            apr_dbm_freedatum(dbm, dbmval);
        } else {
            apr_dbm_delete(dbm, dbmkey);
            deleted++;
        }
        total++;
        apr_dbm_nextkey(dbm, &dbmkey);
    }
    apr_dbm_close(dbm);

    rv = apr_global_mutex_unlock(sc->cache->mutex);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s,
            "[gnutls_cache] Cleaned up cache '%s'. Deleted %d and left %d",
            sc->cache_config, deleted, total - deleted);

    apr_pool_destroy(spool);

    return;
}

static gnutls_datum_t dbm_cache_fetch(mgs_handle_t *ctxt, gnutls_datum_t key)
{
    gnutls_datum_t data = {NULL, 0};
    apr_dbm_t *dbm;
    apr_datum_t dbmkey = {(char*) key.data, key.size};
    apr_datum_t dbmval;
    apr_time_t expiry = 0;
    apr_status_t rv;

    /* check if it is time for cache expiration */
    dbm_cache_expire(ctxt->c->base_server);

    apr_global_mutex_lock(ctxt->sc->cache->mutex);

    rv = apr_dbm_open_ex(&dbm, db_type(ctxt->sc),
            ctxt->sc->cache_config, APR_DBM_READONLY,
            SSL_DBM_FILE_MODE, ctxt->c->pool);
    if (rv != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_NOTICE, rv, ctxt->c,
                      "error opening cache '%s'",
                      ctxt->sc->cache_config);
        apr_global_mutex_unlock(ctxt->sc->cache->mutex);
        return data;
    }

    rv = apr_dbm_fetch(dbm, dbmkey, &dbmval);

    if (rv != APR_SUCCESS)
        goto close_db;

    if (dbmval.dptr == NULL || dbmval.dsize <= sizeof (apr_time_t))
        goto cleanup;

    data.size = dbmval.dsize - sizeof (apr_time_t);
    /* get data expiration tag */
    expiry = *((apr_time_t *) dbmval.dptr);

    data.data = gnutls_malloc(data.size);
    if (data.data == NULL)
        goto cleanup;

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, ctxt->c,
                  "fetched %ld bytes from cache",
                  dbmval.dsize);

    memcpy(data.data, dbmval.dptr + sizeof (apr_time_t), data.size);

 cleanup:
    apr_dbm_freedatum(dbm, dbmval);
 close_db:
    apr_dbm_close(dbm);
    apr_global_mutex_unlock(ctxt->sc->cache->mutex);

    /* cache entry might have expired since last cache cleanup */
    if (expiry != 0 && expiry < apr_time_now())
    {
        gnutls_free(data.data);
        data.data = NULL;
        data.size = 0;
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                      "dropped expired cache data");
    }

    return data;
}

static gnutls_datum_t dbm_cache_fetch_session(void *baton, gnutls_datum_t key)
{
    gnutls_datum_t data = {NULL, 0};
    gnutls_datum_t dbmkey;
    mgs_handle_t *ctxt = baton;

    if (mgs_session_id2dbm(ctxt->c, key.data, key.size, &dbmkey) < 0)
        return data;

    return dbm_cache_fetch(ctxt, dbmkey);
}

static int dbm_cache_store(server_rec *s, gnutls_datum_t key,
                           gnutls_datum_t data, apr_time_t expiry)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    apr_dbm_t *dbm;
    apr_datum_t dbmkey = {(char*) key.data, key.size};
    apr_datum_t dbmval;
    apr_status_t rv;
    apr_pool_t *spool;

    /* check if it is time for cache expiration */
    dbm_cache_expire(s);

    apr_pool_create(&spool, NULL);

    /* create DBM value */
    dbmval.dsize = data.size + sizeof (apr_time_t);
    dbmval.dptr = (char *) apr_palloc(spool, dbmval.dsize);

    /* prepend expiration time */
    memcpy((char *) dbmval.dptr, &expiry, sizeof (apr_time_t));
    memcpy((char *) dbmval.dptr + sizeof (apr_time_t),
            data.data, data.size);

    apr_global_mutex_lock(sc->cache->mutex);

    rv = apr_dbm_open_ex(&dbm, db_type(sc),
                         sc->cache_config, APR_DBM_RWCREATE,
                         SSL_DBM_FILE_MODE, spool);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv, s,
                     "error opening cache '%s'",
                     sc->cache_config);
        apr_global_mutex_unlock(sc->cache->mutex);
        apr_pool_destroy(spool);
        return -1;
    }

    rv = apr_dbm_store(dbm, dbmkey, dbmval);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s,
                     "error storing in cache '%s'",
                     sc->cache_config);
        apr_dbm_close(dbm);
        apr_global_mutex_unlock(sc->cache->mutex);
        apr_pool_destroy(spool);
        return -1;
    }

    apr_dbm_close(dbm);
    apr_global_mutex_unlock(sc->cache->mutex);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s,
                 "stored %ld bytes of data (%ld byte key) in cache '%s'",
                 dbmval.dsize, dbmkey.dsize, sc->cache_config);

    apr_pool_destroy(spool);

    return 0;
}

static int dbm_cache_store_session(void *baton, gnutls_datum_t key,
                                   gnutls_datum_t data)
{
    mgs_handle_t *ctxt = baton;
    gnutls_datum_t dbmkey;

    if (mgs_session_id2dbm(ctxt->c, key.data, key.size, &dbmkey) < 0)
        return -1;

    apr_time_t expiry = apr_time_now() + ctxt->sc->cache_timeout;

    return dbm_cache_store(ctxt->c->base_server, dbmkey, data, expiry);
}

static int dbm_cache_delete(void *baton, gnutls_datum_t key)
{
    apr_dbm_t *dbm;
    gnutls_datum_t tmpkey;
    mgs_handle_t *ctxt = baton;
    apr_status_t rv;

    if (mgs_session_id2dbm(ctxt->c, key.data, key.size, &tmpkey) < 0)
        return -1;
    apr_datum_t dbmkey = {(char*) tmpkey.data, tmpkey.size};

    apr_global_mutex_lock(ctxt->sc->cache->mutex);

    rv = apr_dbm_open_ex(&dbm, db_type(ctxt->sc),
            ctxt->sc->cache_config, APR_DBM_RWCREATE,
            SSL_DBM_FILE_MODE, ctxt->c->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                ctxt->c->base_server,
                "[gnutls_cache] error opening cache '%s'",
                ctxt->sc->cache_config);
        apr_global_mutex_unlock(ctxt->sc->cache->mutex);
        return -1;
    }

    rv = apr_dbm_delete(dbm, dbmkey);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                ctxt->c->base_server,
                "[gnutls_cache] error deleting from cache '%s'",
                ctxt->sc->cache_config);
        apr_dbm_close(dbm);
        apr_global_mutex_unlock(ctxt->sc->cache->mutex);
        return -1;
    }

    apr_dbm_close(dbm);
    apr_global_mutex_unlock(ctxt->sc->cache->mutex);

    return 0;
}

static int dbm_cache_post_config(apr_pool_t * p, server_rec * s,
        mgs_srvconf_rec * sc) {
    apr_status_t rv;
    apr_dbm_t *dbm;
    const char *path1;
    const char *path2;

    rv = apr_dbm_open_ex(&dbm, db_type(sc), sc->cache_config,
            APR_DBM_RWCREATE, SSL_DBM_FILE_MODE, p);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                "GnuTLS: Cannot create DBM Cache at `%s'",
                sc->cache_config);
        return rv;
    }

    apr_dbm_close(dbm);

    apr_dbm_get_usednames_ex(p, db_type(sc), sc->cache_config, &path1,
            &path2);

    /* The Following Code takes logic directly from mod_ssl's DBM Cache */
#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
    /* Running as Root */
    if (path1 && geteuid() == 0) {
        if (0 != chown(path1, ap_unixd_config.user_id, -1))
            ap_log_error(APLOG_MARK, APLOG_NOTICE, -1, s,
                         "GnuTLS: could not chown cache path1 `%s' to uid %d (errno: %d)",
                         path1, ap_unixd_config.user_id, errno);
        if (path2 != NULL) {
            if (0 != chown(path2, ap_unixd_config.user_id, -1))
                ap_log_error(APLOG_MARK, APLOG_NOTICE, -1, s,
                             "GnuTLS: could not chown cache path2 `%s' to uid %d (errno: %d)",
                             path2, ap_unixd_config.user_id, errno);
        }
    }
#endif

    return rv;
}

int mgs_cache_post_config(apr_pool_t * p, server_rec * s,
        mgs_srvconf_rec * sc) {

    /* if GnuTLSCache was never explicitly set: */
    if (sc->cache_type == mgs_cache_unset)
        sc->cache_type = mgs_cache_none;
    /* if GnuTLSCacheTimeout was never explicitly set: */
    if (sc->cache_timeout == -1)
        sc->cache_timeout = apr_time_from_sec(MGS_DEFAULT_CACHE_TIMEOUT);

    /* initialize mutex only once */
    if (sc->cache == NULL)
    {
        sc->cache = apr_palloc(p, sizeof(struct mgs_cache));
        apr_status_t rv = ap_global_mutex_create(&sc->cache->mutex, NULL,
                                                 MGS_CACHE_MUTEX_NAME,
                                                 NULL, s, p, 0);
        if (rv != APR_SUCCESS)
            return rv;
    }

    if (sc->cache_type == mgs_cache_dbm || sc->cache_type == mgs_cache_gdbm)
    {
        sc->cache->store = dbm_cache_store;
        sc->cache->fetch = dbm_cache_fetch;
        return dbm_cache_post_config(p, s, sc);
    }
#if HAVE_APR_MEMCACHE
    else if (sc->cache_type == mgs_cache_memcache)
    {
        sc->cache->store = mc_cache_store_generic;
        sc->cache->fetch = mc_cache_fetch_generic;
    }
#endif

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

    if (sc->cache_type == mgs_cache_dbm
            || sc->cache_type == mgs_cache_gdbm) {
        return 0;
    }
#if HAVE_APR_MEMCACHE
    else if (sc->cache_type == mgs_cache_memcache) {
        return mc_cache_child_init(p, s, sc);
    }
#endif
    return 0;
}

#include <assert.h>

int mgs_cache_session_init(mgs_handle_t * ctxt) {
    if (ctxt->sc->cache_type == mgs_cache_dbm
            || ctxt->sc->cache_type == mgs_cache_gdbm) {
        gnutls_db_set_retrieve_function(ctxt->session,
                dbm_cache_fetch_session);
        gnutls_db_set_remove_function(ctxt->session,
                dbm_cache_delete);
        gnutls_db_set_store_function(ctxt->session,
                dbm_cache_store_session);
        gnutls_db_set_ptr(ctxt->session, ctxt);
    }
#if HAVE_APR_MEMCACHE
    else if (ctxt->sc->cache_type == mgs_cache_memcache) {
        gnutls_db_set_retrieve_function(ctxt->session,
                mc_cache_fetch_session);
        gnutls_db_set_remove_function(ctxt->session,
                mc_cache_delete);
        gnutls_db_set_store_function(ctxt->session,
                mc_cache_store_session);
        gnutls_db_set_ptr(ctxt->session, ctxt);
    }
#endif

    return 0;
}

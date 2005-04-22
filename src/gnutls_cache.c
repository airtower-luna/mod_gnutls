/**
 *  Copyright 2004-2005 Paul Querna
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

#include "mod_gnutls.h"

#if HAVE_APR_MEMCACHE
#include "apr_memcache.h"
#endif

#include "apr_dbm.h"

#include "ap_mpm.h"

#include <unistd.h>
#include <sys/types.h>

#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
#include "unixd.h"
#endif


#define MC_TAG "mod_gnutls:"
#define MC_TAG_LEN \
    (sizeof(MC_TAG))
#define STR_SESSION_LEN (GNUTLS_SESSION_ID_STRING_LEN + MC_TAG_LEN)

static char *gnutls_session_id2sz(unsigned char *id, int idlen,
                               char *str, int strsize)
{
    char *cp;
    int n;
 
    cp = apr_cpystrn(str, MC_TAG, MC_TAG_LEN);
    for (n = 0; n < idlen && n < GNUTLS_MAX_SESSION_ID; n++) {
        apr_snprintf(cp, strsize - (cp-str), "%02X", id[n]);
        cp += 2;
    }
    *cp = '\0';
    return str;
}

char *mod_gnutls_session_id2sz(unsigned char *id, int idlen,
                               char *str, int strsize)
{
    char *cp;
    int n;
    
    cp = str;
    for (n = 0; n < idlen && n < GNUTLS_MAX_SESSION_ID; n++) {
        apr_snprintf(cp, strsize - (cp-str), "%02X", id[n]);
        cp += 2;
    }
    *cp = '\0';
    return str;
}


#if HAVE_APR_MEMCACHE

/**
 * GnuTLS Session Cache using libmemcached
 *
 */

/* The underlying apr_memcache system is thread safe... woohoo */
static apr_memcache_t* mc;

int mc_cache_child_init(apr_pool_t *p, server_rec *s, 
                                mod_gnutls_srvconf_rec *sc)
{
    apr_status_t rv = APR_SUCCESS;
    int thread_limit = 0;
    int nservers = 0;
    char* cache_config;
    char* split;
    char* tok;

    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);

    /* Find all the servers in the first run to get a total count */
    cache_config = apr_pstrdup(p, sc->cache_config);
    split = apr_strtok(cache_config, " ", &tok);
    while (split) {
        nservers++;
        split = apr_strtok(NULL," ", &tok);
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
        apr_memcache_server_t* st;
        char* host_str;
        char* scope_id;
        apr_port_t port;

        rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "[gnutls_cache] Failed to Parse Server: '%s'", split);
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
                                        1,
                                        thread_limit, 
                                        600,
                                        &st);
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

        split = apr_strtok(NULL," ", &tok);
    }
    return rv;
}

static int mc_cache_store(void* baton, gnutls_datum_t key, 
                          gnutls_datum_t data)
{
    apr_status_t rv = APR_SUCCESS;
    mod_gnutls_handle_t *ctxt = baton;
    char buf[STR_SESSION_LEN];
    char* strkey = NULL;
    apr_uint32_t timeout;

    strkey = gnutls_session_id2sz(key.data, key.size, buf, sizeof(buf));
    if(!strkey)
        return -1;

    timeout = apr_time_sec(ctxt->sc->cache_timeout);

    rv = apr_memcache_set(mc, strkey, data.data, data.size, timeout, 0);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error setting key '%s' "
                     "with %d bytes of data", strkey, data.size);
        return -1;
    }

    return 0;
}

static gnutls_datum_t mc_cache_fetch(void* baton, gnutls_datum_t key)
{
    apr_status_t rv = APR_SUCCESS;
    mod_gnutls_handle_t *ctxt = baton;
    char buf[STR_SESSION_LEN];
    char* strkey = NULL;
    char* value;
    apr_size_t value_len;
    gnutls_datum_t data = { NULL, 0 };

    strkey = gnutls_session_id2sz(key.data, key.size, buf, sizeof(buf));
    if (!strkey) {
        return data;
    }

    rv = apr_memcache_getp(mc, ctxt->c->pool, strkey,
                           &value, &value_len, NULL);

    if (rv != APR_SUCCESS) {
#if MOD_GNUTLS_DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error fetching key '%s' ",
                     strkey);
#endif
        data.size = 0;
        data.data = NULL;
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

static int mc_cache_delete(void* baton, gnutls_datum_t key)
{
    apr_status_t rv = APR_SUCCESS;
    mod_gnutls_handle_t *ctxt = baton;
    char buf[STR_SESSION_LEN];
    char* strkey = NULL;

    strkey = gnutls_session_id2sz(key.data, key.size, buf, sizeof(buf));
    if(!strkey)
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

#endif /* have_apr_memcache */

#define SSL_DBM_FILE_MODE ( APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD )

static int dbm_cache_expire(mod_gnutls_handle_t *ctxt)
{
    apr_status_t rv;
    apr_dbm_t *dbm;
    apr_datum_t *keylist;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    apr_time_t ex;
    apr_time_t dtime;
    apr_pool_t* spool;
    int i = 0;
    int keyidx = 0;
    int should_delete = 0;

    apr_pool_create(&spool, ctxt->c->pool);
    ex = apr_time_now();
    
    rv = apr_dbm_open(&dbm, ctxt->sc->cache_config, APR_DBM_READONLY,
                      SSL_DBM_FILE_MODE, spool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error opening cache searcher '%s'",
                     ctxt->sc->cache_config);
        return -1;
    }

#define KEYMAX 128

    keylist = apr_palloc(spool, sizeof(dbmkey)*KEYMAX);

    apr_dbm_firstkey(dbm, &dbmkey);
    while (dbmkey.dptr != NULL) {
        apr_dbm_fetch(dbm, dbmkey, &dbmval);
        if (dbmval.dptr != NULL) {
            if (dbmval.dsize >= sizeof(apr_time_t)) {
                memcpy(&dtime, dbmval.dptr, sizeof(apr_time_t));
                if (dtime < ex) {
                    should_delete = 1;
                }
            }
            else {
                should_delete = 1;
            }
            
            if (should_delete == 1) {
                should_delete = 0;
                keylist[keyidx].dptr = apr_palloc(spool, dbmkey.dsize) ;
                memcpy(keylist[keyidx].dptr, dbmkey.dptr, dbmkey.dsize);
                keylist[keyidx].dsize = dbmkey.dsize;
                keyidx++;
                if (keyidx == KEYMAX) {
                    break;
                }
            }
            
        }
        apr_dbm_nextkey(dbm, &dbmkey);
    }
    apr_dbm_close(dbm);

    rv = apr_dbm_open(&dbm, ctxt->sc->cache_config,
                  APR_DBM_RWCREATE, SSL_DBM_FILE_MODE, spool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                 ctxt->c->base_server,
                 "[gnutls_cache] error opening cache writer '%s'",
                 ctxt->sc->cache_config);
        return -1;
    }

    for (i = 0; i < keyidx; i++) {
        apr_dbm_delete(dbm, keylist[i]);
    }

    apr_dbm_close(dbm);
    apr_pool_destroy(spool);
    
    return 0;
}

static gnutls_datum_t dbm_cache_fetch(void* baton, gnutls_datum_t key)
{
    gnutls_datum_t data = { NULL, 0 };
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    mod_gnutls_handle_t *ctxt = baton;
    apr_status_t rv;

    dbmkey.dptr  = key.data;
    dbmkey.dsize = key.size;

    dbm_cache_expire(ctxt);

    rv = apr_dbm_open(&dbm, ctxt->sc->cache_config,
	              APR_DBM_RWCREATE, SSL_DBM_FILE_MODE, ctxt->c->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error opening cache '%s'",
                     ctxt->sc->cache_config);
        return data;
    }

    rv = apr_dbm_fetch(dbm, dbmkey, &dbmval);
    
    if (rv != APR_SUCCESS) {
        apr_dbm_close(dbm);
        return data;
    }

    if (dbmval.dptr == NULL || dbmval.dsize <= sizeof(apr_time_t)) {
        apr_dbm_close(dbm);
        return data;
    }
    apr_dbm_close(dbm);

    data.size = dbmval.dsize - sizeof(apr_time_t);

    data.data = gnutls_malloc(data.size);
    if (data.data == NULL) {
        return data;
    }
    
    memcpy(data.data, dbmval.dptr+sizeof(apr_time_t), data.size);

    return data;
}

static int dbm_cache_store(void* baton, gnutls_datum_t key, 
                          gnutls_datum_t data)
{
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    mod_gnutls_handle_t *ctxt = baton;
    apr_status_t rv;
    apr_time_t expiry;
    
    dbmkey.dptr  = (char *)key.data;
    dbmkey.dsize = key.size;

    /* create DBM value */
    dbmval.dsize = data.size + sizeof(apr_time_t);
    dbmval.dptr  = (char *)malloc(dbmval.dsize);

    expiry = apr_time_now() + ctxt->sc->cache_timeout;

    memcpy((char *)dbmval.dptr, &expiry, sizeof(apr_time_t));
    memcpy((char *)dbmval.dptr+sizeof(apr_time_t),
           data.data, data.size);

    dbm_cache_expire(ctxt);

    rv = apr_dbm_open(&dbm, ctxt->sc->cache_config,
	              APR_DBM_RWCREATE, SSL_DBM_FILE_MODE, ctxt->c->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error opening cache '%s'",
                     ctxt->sc->cache_config);
        free(dbmval.dptr);        
        return -1;
    }

    rv = apr_dbm_store(dbm, dbmkey, dbmval);
    
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error storing in cache '%s'",
                     ctxt->sc->cache_config);
        apr_dbm_close(dbm);
        free(dbmval.dptr);
        return -1;
    }

    apr_dbm_close(dbm);

    free(dbmval.dptr);
    
    return 0;
}

static int dbm_cache_delete(void* baton, gnutls_datum_t key)
{
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    mod_gnutls_handle_t *ctxt = baton;
    apr_status_t rv;
    
    dbmkey.dptr  = (char *)key.data;
    dbmkey.dsize = key.size;

    dbm_cache_expire(ctxt);
    
    rv = apr_dbm_open(&dbm, ctxt->sc->cache_config,
	              APR_DBM_RWCREATE, SSL_DBM_FILE_MODE, ctxt->c->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error opening cache '%s'",
                     ctxt->sc->cache_config);
        return -1;
    }

    rv = apr_dbm_delete(dbm, dbmkey);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error deleting from cache '%s'",
                     ctxt->sc->cache_config);
        apr_dbm_close(dbm);
        return -1;
    }

    apr_dbm_close(dbm);

    return 0;
}

static int dbm_cache_post_config(apr_pool_t *p, server_rec *s, 
                                mod_gnutls_srvconf_rec *sc)
{
    apr_status_t rv;
    apr_dbm_t *dbm;
    const char* path1;
    const char* path2;

    rv = apr_dbm_open(&dbm, sc->cache_config, APR_DBM_RWCREATE, 
                      SSL_DBM_FILE_MODE, p);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "GnuTLS: Cannot create DBM Cache at `%s'", 
                     sc->cache_config);
        return rv; 
    }

    apr_dbm_close(dbm);

    apr_dbm_get_usednames(p, sc->cache_config, &path1, &path2);

    /* The Following Code takes logic directly from mod_ssl's DBM Cache */ 
#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
    /* Running as Root */
    if (geteuid() == 0)  {
        chown(path1, unixd_config.user_id, -1);
        if (path2 != NULL) { 
            chown(path2, unixd_config.user_id, -1);
        }
    }
#endif

    return rv;
}

int mod_gnutls_cache_post_config(apr_pool_t *p, server_rec *s, 
                                 mod_gnutls_srvconf_rec *sc)
{
    if (sc->cache_type == mod_gnutls_cache_dbm) {
        return dbm_cache_post_config(p, s, sc);
    }
    return 0;
}

int mod_gnutls_cache_child_init(apr_pool_t *p, server_rec *s, 
                                mod_gnutls_srvconf_rec *sc)
{
    if (sc->cache_type == mod_gnutls_cache_dbm) {
        return 0;
    }
#if HAVE_APR_MEMCACHE
    else if (sc->cache_type == mod_gnutls_cache_memcache) { 
        return mc_cache_child_init(p, s, sc);
    }
#endif
    return 0;
}

 #include <assert.h>

int mod_gnutls_cache_session_init(mod_gnutls_handle_t *ctxt)
{
    if (ctxt->sc->cache_type == mod_gnutls_cache_dbm) {
        gnutls_db_set_retrieve_function(ctxt->session, dbm_cache_fetch);
        gnutls_db_set_remove_function(ctxt->session, dbm_cache_delete);
        gnutls_db_set_store_function(ctxt->session, dbm_cache_store);
        gnutls_db_set_ptr(ctxt->session, ctxt);
    }
#if HAVE_APR_MEMCACHE
    else if (ctxt->sc->cache_type == mod_gnutls_cache_memcache) { 
        gnutls_db_set_retrieve_function(ctxt->session, mc_cache_fetch);
        gnutls_db_set_remove_function(ctxt->session, mc_cache_delete);
        gnutls_db_set_store_function(ctxt->session, mc_cache_store);
        gnutls_db_set_ptr(ctxt->session, ctxt);
    }
#endif

    return 0;
}

/* ====================================================================
 *  Copyright 2004 Paul Querna
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
#include "ap_mpm.h"

/**
 * GnuTLS Session Cache using libmemcached
 *
 */

/* The underlying apr_memcache system is thread safe... woohoo */
static apr_memcache_t* mc;

int mod_gnutls_cache_child_init(apr_pool_t *p, server_rec *s, 
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
        char* split2;
        char* host_str;
        char* port_str;
        int port;

        host_str = apr_strtok(split,":", &split2);
        port_str = apr_strtok(NULL,":", &split2);
        if (!port_str) {
            port = 11211; /* default port */
        }
        else {
            port = atoi(port_str);
        }

        /* Should Max Conns be (thread_limit / nservers) ? */
        rv = apr_memcache_server_create(p,
                                        host_str, port,
                                        0,
                                        1,
                                        thread_limit, 
                                        600,
                                        &st);
        if(rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "[gnutls_cache] Failed to Create Server: %s:%d", 
                         host_str, port);
            return rv;
        }

        rv = apr_memcache_add_server(mc, st);
        if(rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "[gnutls_cache] Failed to Add Server: %s:%d", 
                         host_str, port);
            return rv;
        }

        split = apr_strtok(NULL," ", &tok);
    }
    return rv;
}

/* thanks mod_ssl */
#define GNUTLS_SESSION_ID_STRING_LEN \
    ((GNUTLS_MAX_SESSION_ID + 1) * 2)
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


static int cache_store(void* baton, gnutls_datum_t key, gnutls_datum_t data)
{
    apr_status_t rv = APR_SUCCESS;
    mod_gnutls_handle_t *ctxt = baton;
    char buf[STR_SESSION_LEN];
    char* strkey = NULL;
    apr_uint32_t timeout;

    strkey = gnutls_session_id2sz(key.data, key.size, buf, sizeof(buf));
    if(!strkey)
        return -1;

    timeout = 3600;

    rv = apr_memcache_set(mc,  strkey, data.data, data.size, timeout, 0);

    if(rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error setting key '%s' "
                     "with %d bytes of data", strkey, data.size);
        return -1;
    }

    return 0;
}

static gnutls_datum_t cache_fetch(void* baton, gnutls_datum_t key)
{
    apr_status_t rv = APR_SUCCESS;
    mod_gnutls_handle_t *ctxt = baton;
    char buf[STR_SESSION_LEN];
    char* strkey = NULL;
    char* value;
    apr_size_t value_len;
    gnutls_datum_t data = { NULL, 0 };

    strkey = gnutls_session_id2sz(key.data, key.size, buf, sizeof(buf));
    if(!strkey) {
        return data;
    }

    rv = apr_memcache_getp(mc, ctxt->c->pool, strkey,
                           &value, &value_len, NULL);

    if(rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error fetching key '%s' ",
                     strkey);

        data.size = 0;
        data.data = NULL;
        return data;
    }

    /* TODO: Eliminate this memcpy. ffs. gnutls-- */
    data.data = gnutls_malloc(value_len);
    if (data.data == NULL)
        return data;

    data.size = value_len;
    memcpy(data.data, value, value_len);

    return data;
}

static int cache_delete(void* baton, gnutls_datum_t key)
{
    apr_status_t rv = APR_SUCCESS;
    mod_gnutls_handle_t *ctxt = baton;
    char buf[STR_SESSION_LEN];
    char* strkey = NULL;

    strkey = gnutls_session_id2sz(key.data, key.size, buf, sizeof(buf));
    if(!strkey)
        return -1;

    rv = apr_memcache_delete(mc, strkey, 0);

    if(rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv,
                     ctxt->c->base_server,
                     "[gnutls_cache] error deleting key '%s' ",
                      strkey);
        return -1;
    }

    return 0;
}

int mod_gnutls_cache_session_init(mod_gnutls_handle_t *ctxt)
{
    gnutls_db_set_retrieve_function(ctxt->session, cache_fetch);
    gnutls_db_set_remove_function(ctxt->session, cache_delete);
    gnutls_db_set_store_function(ctxt->session, cache_store);
    gnutls_db_set_ptr(ctxt->session, ctxt);
    return 0;
}

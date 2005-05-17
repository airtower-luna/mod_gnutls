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
#include "http_vhost.h"
#include "ap_mpm.h"

#if !USING_2_1_RECENT
extern server_rec *ap_server_conf;
#endif

#if APR_HAS_THREADS
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

#if MOD_GNUTLS_DEBUG
static apr_file_t* debug_log_fp;
#endif

static int mpm_is_threaded;

static apr_status_t mgs_cleanup_pre_config(void *data)
{
    gnutls_global_deinit();
    return APR_SUCCESS;
}

#if MOD_GNUTLS_DEBUG
static void gnutls_debug_log_all( int level, const char* str)
{
    apr_file_printf(debug_log_fp, "<%d> %s\n", level, str);
}
#endif

int mgs_hook_pre_config(apr_pool_t * pconf,
                        apr_pool_t * plog, apr_pool_t * ptemp)
{

#if APR_HAS_THREADS
    ap_mpm_query(AP_MPMQ_IS_THREADED, &mpm_is_threaded);
    if (mpm_is_threaded) {
        gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    }
#else
    mpm_is_threaded = 0;
#endif

    gnutls_global_init();

    apr_pool_cleanup_register(pconf, NULL, mgs_cleanup_pre_config,
                              apr_pool_cleanup_null);

#if MOD_GNUTLS_DEBUG
    apr_file_open(&debug_log_fp, "/tmp/gnutls_debug",
                  APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT, pconf);

    gnutls_global_set_log_level(9);
    gnutls_global_set_log_function(gnutls_debug_log_all);
#endif

    return OK;
}


static gnutls_datum load_params(const char* file, server_rec* s, 
                                apr_pool_t* pool) 
{
    gnutls_datum ret = { NULL, 0 };
    apr_file_t* fp;
    apr_finfo_t finfo;
    apr_status_t rv;
    apr_size_t br = 0;

    rv = apr_file_open(&fp, file, APR_READ|APR_BINARY, APR_OS_DEFAULT, 
                       pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, s, 
                     "GnuTLS failed to load params file at: %s", file);
        return ret;
    }

    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, fp);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, s, 
                     "GnuTLS failed to stat params file at: %s", file);
        return ret;
    }

    ret.data = apr_palloc(pool, finfo.size+1);
    rv = apr_file_read_full(fp, ret.data, finfo.size, &br);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, s, 
                     "GnuTLS failed to read params file at: %s", file);
        return ret;
    }
    apr_file_close(fp);
    ret.data[br] = '\0';
    ret.size = br;

    return ret;
}

int mgs_hook_post_config(apr_pool_t * p, apr_pool_t * plog,
                                       apr_pool_t * ptemp,
                                       server_rec * base_server)
{
    int rv;
    int data_len;
    server_rec *s;
    gnutls_dh_params_t dh_params;
    gnutls_rsa_params_t rsa_params;
    mgs_srvconf_rec *sc;
    mgs_srvconf_rec *sc_base;
    void *data = NULL;
    int first_run = 0;
    const char *userdata_key = "mgs_init";
         
    apr_pool_userdata_get(&data, userdata_key, base_server->process->pool);
    if (data == NULL) {
        first_run = 1;
        apr_pool_userdata_set((const void *)1, userdata_key, 
                              apr_pool_cleanup_null, 
                              base_server->process->pool);
    }


    {
        gnutls_datum pdata;
        apr_pool_t* tpool;
        s = base_server;
        sc_base = (mgs_srvconf_rec *) ap_get_module_config(s->module_config,
                                                             &gnutls_module);

        apr_pool_create(&tpool, p);

        gnutls_dh_params_init(&dh_params);

        pdata = load_params(sc_base->dh_params_file, s, tpool);

        if (pdata.size != 0) {
            rv = gnutls_dh_params_import_pkcs3(dh_params, &pdata, 
                                               GNUTLS_X509_FMT_PEM);
            if (rv != 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s, 
                             "GnuTLS: Unable to load DH Params: (%d) %s",
                             rv, gnutls_strerror(rv));
                exit(rv);
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s, 
                         "GnuTLS: Unable to load DH Params."
                         " Shutting Down.");
            exit(-1);
        }
        apr_pool_clear(tpool);

        gnutls_rsa_params_init(&rsa_params);

        pdata = load_params(sc_base->rsa_params_file, s, tpool);

        if (pdata.size != 0) {
            rv = gnutls_rsa_params_import_pkcs1(rsa_params, &pdata, 
                                                GNUTLS_X509_FMT_PEM);
            if (rv != 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s, 
                             "GnuTLS: Unable to load RSA Params: (%d) %s",
                             rv, gnutls_strerror(rv));
                exit(rv);
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s, 
                         "GnuTLS: Unable to load RSA Params."
                         " Shutting Down.");
            exit(-1);
        }

        apr_pool_destroy(tpool);
        rv = mgs_cache_post_config(p, s, sc_base);
        if (rv != 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, s, 
                         "GnuTLS: Post Config for GnuTLSCache Failed."
                         " Shutting Down.");
            exit(-1);
        }
         
        for (s = base_server; s; s = s->next) {
            sc = (mgs_srvconf_rec *) ap_get_module_config(s->module_config,
                                                                 &gnutls_module);
            sc->cache_type = sc_base->cache_type;
            sc->cache_config = sc_base->cache_config;

            gnutls_certificate_set_rsa_export_params(sc->certs, 
                                                     rsa_params);
            gnutls_certificate_set_dh_params(sc->certs, dh_params);

            if (sc->cert_x509 == NULL && sc->enabled == GNUTLS_ENABLED_TRUE) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                             "[GnuTLS] - Host '%s:%d' is missing a "
                             "Certificate File!",
                         s->server_hostname, s->port);
                exit(-1);
            }
            
            if (sc->privkey_x509 == NULL && sc->enabled == GNUTLS_ENABLED_TRUE) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                             "[GnuTLS] - Host '%s:%d' is missing a "
                             "Private Key File!",
                             s->server_hostname, s->port);
                exit(-1);
            }
            
            rv = gnutls_x509_crt_get_dn_by_oid(sc->cert_x509, 
                                               GNUTLS_OID_X520_COMMON_NAME, 0, 0,
                                               NULL, &data_len);
            
            if (data_len < 1) {
                sc->enabled = GNUTLS_ENABLED_FALSE;
                sc->cert_cn = NULL;
                continue;
            }
            
            sc->cert_cn = apr_palloc(p, data_len);
            rv = gnutls_x509_crt_get_dn_by_oid(sc->cert_x509, 
                                               GNUTLS_OID_X520_COMMON_NAME, 0, 0,
                                               sc->cert_cn, &data_len);
        }
    }

    ap_add_version_component(p, "mod_gnutls/" MOD_GNUTLS_VERSION);

    return OK;
}

void mgs_hook_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv = APR_SUCCESS;
    mgs_srvconf_rec *sc = ap_get_module_config(s->module_config,
                                                      &gnutls_module);

    if (sc->cache_type != mgs_cache_none) {
        rv = mgs_cache_child_init(p, s, sc);
        if(rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                             "[GnuTLS] - Failed to run Cache Init");
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "[GnuTLS] - No Cache Configured. Hint: GnuTLSCache");
    }
}

const char *mgs_hook_http_scheme(const request_rec * r)
{
    mgs_srvconf_rec *sc =
        (mgs_srvconf_rec *) ap_get_module_config(r->server->
                                                        module_config,
                                                        &gnutls_module);

    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return NULL;
    }

    return "https";
}

apr_port_t mgs_hook_default_port(const request_rec * r)
{
    mgs_srvconf_rec *sc =
        (mgs_srvconf_rec *) ap_get_module_config(r->server->
                                                        module_config,
                                                        &gnutls_module);

    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return 0;
    }

    return 443;
}

#define MAX_HOST_LEN 255

#if USING_2_1_RECENT
typedef struct
{
    mgs_handle_t *ctxt;
    mgs_srvconf_rec *sc;
    const char* sni_name;
} vhost_cb_rec;

static int vhost_cb (void* baton, conn_rec* conn, server_rec* s)
{
    mgs_srvconf_rec *tsc;
    vhost_cb_rec* x = baton;

    tsc = (mgs_srvconf_rec *) ap_get_module_config(s->module_config,
                                                          &gnutls_module);
    
    if (tsc->enabled != GNUTLS_ENABLED_TRUE || tsc->cert_cn == NULL) {
        return 0;
    }
    
    /* The CN can contain a * -- this will match those too. */
    if (ap_strcasecmp_match(x->sni_name, tsc->cert_cn) == 0) {
        /* found a match */
#if MOD_GNUTLS_DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                     x->ctxt->c->base_server,
                     "GnuTLS: Virtual Host CB: "
                     "'%s' == '%s'", tsc->cert_cn, x->sni_name);
#endif
        /* Because we actually change the server used here, we need to reset
         * things like ClientVerify.
         */
        x->sc = tsc;
        /* Shit. Crap. Dammit. We *really* should rehandshake here, as our
         * certificate structure *should* change when the server changes. 
         * acccckkkkkk. 
         */
        return 1;
    }
    return 0;
}
#endif

mgs_srvconf_rec* mgs_find_sni_server(gnutls_session_t session) 
{
    int rv;
    int sni_type;
    int data_len = MAX_HOST_LEN;
    char sni_name[MAX_HOST_LEN];
    mgs_handle_t *ctxt;
#if USING_2_1_RECENT
    vhost_cb_rec cbx;
#else
    server_rec* s;
    mgs_srvconf_rec *tsc;    
#endif
    
    ctxt = gnutls_transport_get_ptr(session);
    
    sni_type = gnutls_certificate_type_get(session);
    if (sni_type != GNUTLS_CRT_X509) {
        /* In theory, we could support OpenPGP Certificates. Theory != code. */
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0,
                     ctxt->c->base_server,
                     "GnuTLS: Only x509 Certificates are currently supported.");
        return NULL;
    }
    
    rv = gnutls_server_name_get(ctxt->session, sni_name, 
                                &data_len, &sni_type, 0);
    
    if (rv != 0) {
        return NULL;
    }
    
    if (sni_type != GNUTLS_NAME_DNS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0,
                     ctxt->c->base_server,
                     "GnuTLS: Unknown type '%d' for SNI: "
                     "'%s'", sni_type, sni_name);
        return NULL;
    }
    
    /**
     * Code in the Core already sets up the c->base_server as the base
     * for this IP/Port combo.  Trust that the core did the 'right' thing.
     */
#if USING_2_1_RECENT
    cbx.ctxt = ctxt;
    cbx.sc = NULL;
    cbx.sni_name = sni_name;
    
    rv = ap_vhost_iterate_given_conn(ctxt->c, vhost_cb, &cbx);
    if (rv == 1) {
        return cbx.sc;
    }
#else
    for (s = ap_server_conf; s; s = s->next) {
        
        tsc = (mgs_srvconf_rec *) ap_get_module_config(s->module_config,
                                                       &gnutls_module);
        if (tsc->enabled != GNUTLS_ENABLED_TRUE) {
            continue;
        }
#if MOD_GNUTLS_DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                     ctxt->c->base_server,
                     "GnuTLS: sni-x509 cn: %s/%d pk: %s s: 0x%08X s->n: 0x%08X  sc: 0x%08X", tsc->cert_cn, rv,
                     gnutls_pk_algorithm_get_name(gnutls_x509_privkey_get_pk_algorithm(ctxt->sc->privkey_x509)),
                     (unsigned int)s, (unsigned int)s->next, (unsigned int)tsc);
#endif            
        /* The CN can contain a * -- this will match those too. */
        if (ap_strcasecmp_match(sni_name, tsc->cert_cn) == 0) {
#if MOD_GNUTLS_DEBUG
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                         ctxt->c->base_server,
                         "GnuTLS: Virtual Host: "
                         "'%s' == '%s'", tsc->cert_cn, sni_name);
#endif
            return tsc;
        }
    }
#endif
    return NULL;
}


static int cert_retrieve_fn(gnutls_session_t session, gnutls_retr_st* ret) 
{
    mgs_handle_t *ctxt;
    mgs_srvconf_rec *tsc;
    
    ctxt = gnutls_transport_get_ptr(session);

    ret->type = GNUTLS_CRT_X509;
    ret->ncerts = 1;
    ret->deinit_all = 0;

    tsc = mgs_find_sni_server(session);
    
    if (tsc != NULL) {
        ctxt->sc = tsc;
        gnutls_certificate_server_set_request(ctxt->session, ctxt->sc->client_verify_mode);
    }
    
    ret->cert.x509 = &ctxt->sc->cert_x509;
    ret->key.x509 = ctxt->sc->privkey_x509;
    return 0;
}

static mgs_handle_t* create_gnutls_handle(apr_pool_t* pool, conn_rec * c)
{
    mgs_handle_t *ctxt;
    mgs_srvconf_rec *sc =
        (mgs_srvconf_rec *) ap_get_module_config(c->base_server->
                                                        module_config,
                                                        &gnutls_module);

    ctxt = apr_pcalloc(pool, sizeof(*ctxt));
    ctxt->c = c;
    ctxt->sc = sc;
    ctxt->status = 0;

    ctxt->input_rc = APR_SUCCESS;
    ctxt->input_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    ctxt->input_cbuf.length = 0;

    ctxt->output_rc = APR_SUCCESS;
    ctxt->output_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    ctxt->output_blen = 0;
    ctxt->output_length = 0;

    gnutls_init(&ctxt->session, GNUTLS_SERVER);

    gnutls_protocol_set_priority(ctxt->session, sc->protocol);
    gnutls_cipher_set_priority(ctxt->session, sc->ciphers);
    gnutls_compression_set_priority(ctxt->session, sc->compression);
    gnutls_kx_set_priority(ctxt->session, sc->key_exchange);
    gnutls_mac_set_priority(ctxt->session, sc->macs);
    gnutls_certificate_type_set_priority(ctxt->session, sc->cert_types);

    mgs_cache_session_init(ctxt);
    
    gnutls_credentials_set(ctxt->session, GNUTLS_CRD_CERTIFICATE, ctxt->sc->certs);

    gnutls_certificate_server_set_retrieve_function(sc->certs, cert_retrieve_fn);
    gnutls_certificate_server_set_request(ctxt->session, ctxt->sc->client_verify_mode);
    return ctxt;
}

int mgs_hook_pre_connection(conn_rec * c, void *csd)
{
    mgs_handle_t *ctxt;
    mgs_srvconf_rec *sc =
        (mgs_srvconf_rec *) ap_get_module_config(c->base_server->
                                                        module_config,
                                                        &gnutls_module);

    if (!(sc && (sc->enabled == GNUTLS_ENABLED_TRUE))) {
        return DECLINED;
    }

    ctxt = create_gnutls_handle(c->pool, c);

    ap_set_module_config(c->conn_config, &gnutls_module, ctxt);

    gnutls_transport_set_pull_function(ctxt->session,
                                       mgs_transport_read);
    gnutls_transport_set_push_function(ctxt->session,
                                       mgs_transport_write);
    gnutls_transport_set_ptr(ctxt->session, ctxt);
    
    ctxt->input_filter = ap_add_input_filter(GNUTLS_INPUT_FILTER_NAME, ctxt, 
                                             NULL, c);
    ctxt->output_filter = ap_add_output_filter(GNUTLS_OUTPUT_FILTER_NAME, ctxt,
                                               NULL, c);

    return OK;
}

int mgs_hook_fixups(request_rec *r)
{
    unsigned char sbuf[GNUTLS_MAX_SESSION_ID];
    char buf[AP_IOBUFSIZE];
    const char* tmp;
    int len;
    mgs_handle_t *ctxt;
    int rv = OK;
    
    apr_table_t *env = r->subprocess_env;

    ctxt = ap_get_module_config(r->connection->conn_config, &gnutls_module);

    if(!ctxt) {
        return DECLINED;
    }

    apr_table_setn(env, "HTTPS", "on");

    apr_table_setn(env, "GNUTLS_VERSION_INTERFACE", MOD_GNUTLS_VERSION);
    apr_table_setn(env, "GNUTLS_VERSION_LIBRARY", LIBGNUTLS_VERSION);

    apr_table_setn(env, "SSL_PROTOCOL",
                   gnutls_protocol_get_name(gnutls_protocol_get_version(ctxt->session)));

    apr_table_setn(env, "SSL_CIPHER",
                   gnutls_cipher_get_name(gnutls_cipher_get(ctxt->session)));

    apr_table_setn(env, "SSL_CLIENT_VERIFY", "NONE");

    tmp = apr_psprintf(r->pool, "%d",
              8 * gnutls_cipher_get_key_size(gnutls_cipher_get(ctxt->session)));

    apr_table_setn(env, "SSL_CIPHER_USEKEYSIZE", tmp);

    apr_table_setn(env, "SSL_CIPHER_ALGKEYSIZE", tmp);

    len = sizeof(sbuf);
    gnutls_session_get_id(ctxt->session, sbuf, &len);
    tmp = mgs_session_id2sz(sbuf, len, buf, sizeof(buf));
    apr_table_setn(env, "SSL_SESSION_ID", apr_pstrdup(r->pool, tmp));

    /* TODO: There are many other env vars that we need to add */
    {
        len = sizeof(buf);
        gnutls_x509_crt_get_dn(ctxt->sc->cert_x509, buf, &len);
        apr_table_setn(env, "SSL_SERVER_S_DN", apr_pstrmemdup(r->pool, buf, len));
           
        len = sizeof(buf);
        gnutls_x509_crt_get_issuer_dn(ctxt->sc->cert_x509, buf, &len);
        apr_table_setn(env, "SSL_SERVER_I_DN", apr_pstrmemdup(r->pool, buf, len));
    }
    return rv;
}

int mgs_hook_authz(request_rec *r)
{
    int rv;
    int status;
    mgs_handle_t *ctxt;
    mgs_dirconf_rec *dc = ap_get_module_config(r->per_dir_config,
                                                      &gnutls_module);
    
    ctxt = ap_get_module_config(r->connection->conn_config, &gnutls_module);
    
    if (!ctxt) {
        return DECLINED;
    }
    ap_add_common_vars(r);
    mgs_hook_fixups(r);
    status = mgs_authz_lua(r);
    if (status != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "GnuTLS: FAILED Lua Authorization Test");
        return HTTP_FORBIDDEN;
    }
    if (dc->client_verify_mode == GNUTLS_CERT_IGNORE) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "GnuTLS: Directory set to Ignore Client Certificate!");
        return DECLINED;
    }

    if (ctxt->sc->client_verify_mode < dc->client_verify_mode) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                     "GnuTLS: Attempting to rehandshake with peer. %d %d",
                      ctxt->sc->client_verify_mode, dc->client_verify_mode);
        
        gnutls_certificate_server_set_request(ctxt->session,
                                              dc->client_verify_mode);
    
        if (mgs_rehandshake(ctxt) != 0) {
            return HTTP_FORBIDDEN;
        }
    }
    else if (ctxt->sc->client_verify_mode == GNUTLS_CERT_IGNORE) {
#if MOD_GNUTLS_DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                      "GnuTLS: Peer is set to IGNORE");
#endif
        return DECLINED;
    }
    
    rv = gnutls_certificate_verify_peers2(ctxt->session, &status);

    if (rv < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                     "GnuTLS: Failed to Verify Peer: (%d) %s", 
                     rv, gnutls_strerror(rv));
        return HTTP_FORBIDDEN;
    }
    
    if (status < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                     "GnuTLS: Peer Status is invalid."); 
        return HTTP_FORBIDDEN;
    }
    
    if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                     "GnuTLS: Could not find Signer for Peer Certificate"); 
    }
    
    if (status & GNUTLS_CERT_SIGNER_NOT_CA) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                     "GnuTLS: Could not find CA for Peer Certificate"); 
    }
    
    if (status & GNUTLS_CERT_INVALID) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                     "GnuTLS: Peer Certificate is invalid."); 
        return HTTP_FORBIDDEN;
    }
    else if (status & GNUTLS_CERT_REVOKED) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                     "GnuTLS: Peer Certificate is revoked."); 
        return HTTP_FORBIDDEN;
    }
    
    /* TODO: OpenPGP Certificates */
    if (gnutls_certificate_type_get(ctxt->session) != GNUTLS_CRT_X509) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, 
                     "GnuTLS: Only x509 is supported for client certificates");         
        return HTTP_FORBIDDEN;
    }
    /* TODO: Further Verification. */
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, 
                 "GnuTLS: Verified Peer.");             
    return OK;
}


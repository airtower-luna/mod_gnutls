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

#if APR_HAS_THREADS
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

static apr_file_t* debug_log_fp;

static apr_status_t mod_gnutls_cleanup_pre_config(void *data)
{
    gnutls_global_deinit();
    return APR_SUCCESS;
}

static void gnutls_debug_log_all( int level, const char* str)
{
    apr_file_printf(debug_log_fp, "<%d> %s\n", level, str);
}

static int mod_gnutls_hook_pre_config(apr_pool_t * pconf,
                                      apr_pool_t * plog, apr_pool_t * ptemp)
{

#if APR_HAS_THREADS
    /* TODO: Check MPM Type here */
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif

    gnutls_global_init();

    apr_pool_cleanup_register(pconf, NULL, mod_gnutls_cleanup_pre_config,
                              apr_pool_cleanup_null);

    apr_file_open(&debug_log_fp, "/tmp/gnutls_debug",
                  APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT, pconf);

    gnutls_global_set_log_level(9);
    gnutls_global_set_log_function(gnutls_debug_log_all);

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

    ret.data[br] = '\0';
    ret.size = br;

    return ret;
}

static int mod_gnutls_hook_post_config(apr_pool_t * p, apr_pool_t * plog,
                                       apr_pool_t * ptemp,
                                       server_rec * base_server)
{
    int rv;
    server_rec *s;
    gnutls_dh_params_t dh_params;
    gnutls_rsa_params_t rsa_params;
    mod_gnutls_srvconf_rec *sc;
    mod_gnutls_srvconf_rec *sc_base;
    void *data = NULL;
    int first_run = 0;
    const char *userdata_key = "mod_gnutls_init";
         
    apr_pool_userdata_get(&data, userdata_key, base_server->process->pool);
    if (data == NULL) {
        first_run = 1;
        apr_pool_userdata_set((const void *)1, userdata_key, 
                              apr_pool_cleanup_null, 
                              base_server->process->pool);
    }


    if (!first_run) {
        gnutls_datum pdata;
        apr_pool_t* tpool;
        s = base_server;
        sc_base = (mod_gnutls_srvconf_rec *) ap_get_module_config(s->module_config,
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
        rv = mod_gnutls_cache_post_config(p, s, sc_base);
        if (rv != 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, s, 
                         "GnuTLS: Post Config for GnuTLSCache Failed."
                         " Shutting Down.");
            exit(-1);
        }
         
        for (s = base_server; s; s = s->next) {
            sc = (mod_gnutls_srvconf_rec *) ap_get_module_config(s->module_config,
                                                                 &gnutls_module);
            sc->cache_type = sc_base->cache_type;
            sc->cache_config = sc_base->cache_config;

            if (sc->cert_file != NULL && sc->key_file != NULL) {
                rv = gnutls_certificate_set_x509_key_file(sc->certs, sc->cert_file,
                                                 sc->key_file,
                                                 GNUTLS_X509_FMT_PEM);
                if (rv != 0) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                         "[GnuTLS] - Host '%s:%d' has an invalid key or certificate:"
                         "(%s,%s) (%d) %s",
                         s->server_hostname, s->port, sc->cert_file, sc->key_file,
                         rv, gnutls_strerror(rv));
                }
                else {
                    gnutls_certificate_set_rsa_export_params(sc->certs, 
                                                     rsa_params);
                    gnutls_certificate_set_dh_params(sc->certs, dh_params);
                }
            }
            else if (sc->enabled == GNUTLS_ENABLED_TRUE) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                             "[GnuTLS] - Host '%s:%d' is missing a "
                             "Cert and Key File!",
                         s->server_hostname, s->port);
            }
        }
    } /* first_run */

    ap_add_version_component(p, "GnuTLS/" LIBGNUTLS_VERSION);

    return OK;
}

static void mod_gnutls_hook_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv = APR_SUCCESS;
    mod_gnutls_srvconf_rec *sc = ap_get_module_config(s->module_config,
                                                      &gnutls_module);

    if (sc->cache_type != mod_gnutls_cache_none) {
        rv = mod_gnutls_cache_child_init(p, s, sc);
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

static const char *mod_gnutls_hook_http_scheme(const request_rec * r)
{
    mod_gnutls_srvconf_rec *sc =
        (mod_gnutls_srvconf_rec *) ap_get_module_config(r->server->
                                                        module_config,
                                                        &gnutls_module);

    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return NULL;
    }

    return "https";
}

static apr_port_t mod_gnutls_hook_default_port(const request_rec * r)
{
    mod_gnutls_srvconf_rec *sc =
        (mod_gnutls_srvconf_rec *) ap_get_module_config(r->server->
                                                        module_config,
                                                        &gnutls_module);

    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return 0;
    }

    return 443;
}

static mod_gnutls_handle_t* create_gnutls_handle(apr_pool_t* pool, conn_rec * c)
{
    mod_gnutls_handle_t *ctxt;
    mod_gnutls_srvconf_rec *sc =
        (mod_gnutls_srvconf_rec *) ap_get_module_config(c->base_server->
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

    gnutls_credentials_set(ctxt->session, GNUTLS_CRD_CERTIFICATE, sc->certs);

//  if(anon) {
//    gnutls_credentials_set(ctxt->session, GNUTLS_CRD_ANON, sc->anoncred);
//  }

    gnutls_certificate_server_set_request(ctxt->session, GNUTLS_CERT_IGNORE);

    mod_gnutls_cache_session_init(ctxt);
    return ctxt;
}

static int mod_gnutls_hook_pre_connection(conn_rec * c, void *csd)
{
    mod_gnutls_handle_t *ctxt;
    mod_gnutls_srvconf_rec *sc =
        (mod_gnutls_srvconf_rec *) ap_get_module_config(c->base_server->
                                                        module_config,
                                                        &gnutls_module);

    if (!(sc && (sc->enabled == GNUTLS_ENABLED_TRUE))) {
        return DECLINED;
    }

    ctxt = create_gnutls_handle(c->pool, c);

    ap_set_module_config(c->conn_config, &gnutls_module, ctxt);

    gnutls_transport_set_pull_function(ctxt->session,
                                       mod_gnutls_transport_read);
    gnutls_transport_set_push_function(ctxt->session,
                                       mod_gnutls_transport_write);
    gnutls_transport_set_ptr(ctxt->session, ctxt);
    
    ctxt->input_filter = ap_add_input_filter(GNUTLS_INPUT_FILTER_NAME, ctxt, 
                                             NULL, c);
    ctxt->output_filter = ap_add_output_filter(GNUTLS_OUTPUT_FILTER_NAME, ctxt,
                                               NULL, c);

    return OK;
}

static int mod_gnutls_hook_fixups(request_rec *r)
{
    const char* tmp;
    mod_gnutls_handle_t *ctxt;
    apr_table_t *env = r->subprocess_env;

    ctxt = ap_get_module_config(r->connection->conn_config, &gnutls_module);

    if(!ctxt) {
        return DECLINED;
    }

    apr_table_setn(env, "HTTPS", "on");
    apr_table_setn(env, "SSL_PROTOCOL",
                   gnutls_protocol_get_name(gnutls_protocol_get_version(ctxt->session)));
    apr_table_setn(env, "SSL_CIPHER",
                   gnutls_cipher_get_name(gnutls_cipher_get(ctxt->session)));

    tmp = apr_psprintf(r->pool, "%d",
              8 * gnutls_cipher_get_key_size(gnutls_cipher_get(ctxt->session)));

    apr_table_setn(env, "SSL_CIPHER_USEKEYSIZE", tmp);
    apr_table_setn(env, "SSL_CIPHER_ALGKEYSIZE", tmp);

    return OK;
}

static const char *gnutls_set_cert_file(cmd_parms * parms, void *dummy,
                                        const char *arg)
{
    mod_gnutls_srvconf_rec *sc =
        (mod_gnutls_srvconf_rec *) ap_get_module_config(parms->server->
                                                        module_config,
                                                        &gnutls_module);
    sc->cert_file = ap_server_root_relative(parms->pool, arg);
    return NULL;
}

static const char *gnutls_set_key_file(cmd_parms * parms, void *dummy,
                                       const char *arg)
{
    mod_gnutls_srvconf_rec *sc =
        (mod_gnutls_srvconf_rec *) ap_get_module_config(parms->server->
                                                        module_config,
                                                        &gnutls_module);
    sc->key_file = ap_server_root_relative(parms->pool, arg);
    return NULL;
}

static const char *gnutls_set_cache(cmd_parms * parms, void *dummy,
                                       const char *type, const char* arg)
{
    const char* err;
    mod_gnutls_srvconf_rec *sc = ap_get_module_config(parms->server->
                                                        module_config,
                                                        &gnutls_module);
    if ((err = ap_check_cmd_context(parms, GLOBAL_ONLY))) {
        return err;
    }

    if (strcasecmp("none", type) == 0) {
        sc->cache_type = mod_gnutls_cache_none;
    }
    else if (strcasecmp("dbm", type) == 0) {
        sc->cache_type = mod_gnutls_cache_dbm;
    }
#if HAVE_APR_MEMCACHE
    else if (strcasecmp("memcache", type) == 0) {
        sc->cache_type = mod_gnutls_cache_memcache;
    }
#endif
    else {
        return "Invalid Type for GnuTLSCache!";
    }

    if (sc->cache_type == mod_gnutls_cache_dbm) {
        sc->cache_config = ap_server_root_relative(parms->pool, arg);
    }
    else {
        sc->cache_config = apr_pstrdup(parms->pool, arg);
    }

    return NULL;
}

static const char *gnutls_set_enabled(cmd_parms * parms, void *dummy,
                                      const char *arg)
{
    mod_gnutls_srvconf_rec *sc =
        (mod_gnutls_srvconf_rec *) ap_get_module_config(parms->server->
                                                        module_config,
                                                        &gnutls_module);
    if (!strcasecmp(arg, "On")) {
        sc->enabled = GNUTLS_ENABLED_TRUE;
    }
    else if (!strcasecmp(arg, "Off")) {
        sc->enabled = GNUTLS_ENABLED_FALSE;
    }
    else {
        return "GnuTLSEnable must be set to 'On' or 'Off'";
    }

    return NULL;
}

static const command_rec gnutls_cmds[] = {
    AP_INIT_TAKE1("GnuTLSCertificateFile", gnutls_set_cert_file,
                  NULL,
                  RSRC_CONF,
                  "SSL Server Key file"),
    AP_INIT_TAKE1("GnuTLSKeyFile", gnutls_set_key_file,
                  NULL,
                  RSRC_CONF,
                  "SSL Server Certificate file"),
    AP_INIT_TAKE2("GnuTLSCache", gnutls_set_cache,
                  NULL,
                  RSRC_CONF,
                  "Cache Configuration"),
    AP_INIT_TAKE1("GnuTLSEnable", gnutls_set_enabled,
                  NULL, RSRC_CONF,
                  "Whether this server has GnuTLS Enabled. Default: Off"),

    {NULL}
};

/* TODO: CACertificateFile & Client Authentication
 *    AP_INIT_TAKE1("GnuTLSCACertificateFile", ap_set_server_string_slot,
 *                 (void *) APR_OFFSETOF(gnutls_srvconf_rec, key_file), NULL,
 *                 RSRC_CONF,
 *                 "CA"),
 */

static void gnutls_hooks(apr_pool_t * p)
{
    ap_hook_pre_connection(mod_gnutls_hook_pre_connection, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_post_config(mod_gnutls_hook_post_config, NULL, NULL,
                        APR_HOOK_MIDDLE);
    ap_hook_child_init(mod_gnutls_hook_child_init, NULL, NULL,
                        APR_HOOK_MIDDLE);
    ap_hook_http_scheme(mod_gnutls_hook_http_scheme, NULL, NULL,
                        APR_HOOK_MIDDLE);
    ap_hook_default_port(mod_gnutls_hook_default_port, NULL, NULL,
                         APR_HOOK_MIDDLE);
    ap_hook_pre_config(mod_gnutls_hook_pre_config, NULL, NULL,
                       APR_HOOK_MIDDLE);

    ap_hook_fixups(mod_gnutls_hook_fixups, NULL, NULL, APR_HOOK_MIDDLE);

    /* TODO: HTTP Upgrade Filter */
    /* ap_register_output_filter ("UPGRADE_FILTER", 
     *          ssl_io_filter_Upgrade, NULL, AP_FTYPE_PROTOCOL + 5);
     */
    ap_register_input_filter(GNUTLS_INPUT_FILTER_NAME,
                             mod_gnutls_filter_input, NULL,
                             AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter(GNUTLS_OUTPUT_FILTER_NAME,
                              mod_gnutls_filter_output, NULL,
                              AP_FTYPE_CONNECTION + 5);
}

static void *gnutls_config_server_create(apr_pool_t * p, server_rec * s)
{
    int i;
    mod_gnutls_srvconf_rec *sc = apr_pcalloc(p, sizeof(*sc));

    sc->enabled = GNUTLS_ENABLED_FALSE;

    gnutls_certificate_allocate_credentials(&sc->certs);
    gnutls_anon_allocate_server_credentials(&sc->anoncred);
    sc->key_file = NULL;
    sc->cert_file = NULL;
    sc->cache_timeout = apr_time_from_sec(3600);
    sc->cache_type = mod_gnutls_cache_dbm;
    sc->cache_config = ap_server_root_relative(p, "conf/gnutls_cache");

    /* TODO: Make this Configurable ! */
    sc->dh_params_file = ap_server_root_relative(p, "conf/dhfile");
    sc->rsa_params_file = ap_server_root_relative(p, "conf/rsafile");

    /* TODO: Make this Configurable ! */
    /* meh. mod_ssl uses a flex based parser for this part.. sigh */
    i = 0;
    sc->ciphers[i++] = GNUTLS_CIPHER_AES_256_CBC;
    sc->ciphers[i++] = GNUTLS_CIPHER_AES_128_CBC;
    sc->ciphers[i++] = GNUTLS_CIPHER_ARCFOUR_128;
    sc->ciphers[i++] = GNUTLS_CIPHER_3DES_CBC;
    sc->ciphers[i++] = GNUTLS_CIPHER_ARCFOUR_40;
    sc->ciphers[i] = 0;

    i = 0;
    sc->key_exchange[i++] = GNUTLS_KX_RSA;
    sc->key_exchange[i++] = GNUTLS_KX_RSA_EXPORT;
    sc->key_exchange[i++] = GNUTLS_KX_DHE_DSS;
    sc->key_exchange[i++] = GNUTLS_KX_DHE_RSA;
    sc->key_exchange[i++] = GNUTLS_KX_ANON_DH;
    sc->key_exchange[i++] = GNUTLS_KX_SRP;
    sc->key_exchange[i++] = GNUTLS_KX_SRP_RSA;
    sc->key_exchange[i++] = GNUTLS_KX_SRP_DSS;
    sc->key_exchange[i] = 0;

    i = 0;
    sc->macs[i++] = GNUTLS_MAC_SHA;
    sc->macs[i++] = GNUTLS_MAC_MD5;
    sc->macs[i++] = GNUTLS_MAC_RMD160;
    sc->macs[i] = 0;

    i = 0;
    sc->protocol[i++] = GNUTLS_TLS1_1;
    sc->protocol[i++] = GNUTLS_TLS1;
    sc->protocol[i++] = GNUTLS_SSL3;
    sc->protocol[i] = 0;

    i = 0;
    sc->compression[i++] = GNUTLS_COMP_NULL;
    sc->compression[i++] = GNUTLS_COMP_ZLIB;
    sc->compression[i++] = GNUTLS_COMP_LZO;
    sc->compression[i] = 0;

    i = 0;
    sc->cert_types[i++] = GNUTLS_CRT_X509;
    sc->cert_types[i] = 0;
 
    return sc;
}



module AP_MODULE_DECLARE_DATA gnutls_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    gnutls_config_server_create,
    NULL,
/*    gnutls_config_server_merge, */
    gnutls_cmds,
    gnutls_hooks
};

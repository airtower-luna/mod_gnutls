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

#if APR_HAS_THREADS
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

static apr_status_t gnutls_cleanup_pre_config(void *data)
{
    gnutls_global_deinit();
    return APR_SUCCESS;
}

static int gnutls_hook_pre_config(apr_pool_t * pconf,
                                  apr_pool_t * plog, apr_pool_t * ptemp)
{

#if APR_HAS_THREADS
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif

    gnutls_global_init();

    apr_pool_cleanup_register(pconf, NULL, gnutls_cleanup_pre_config,
                              apr_pool_cleanup_null);

    return OK;
}

#define DH_BITS 1024
#define RSA_BITS 512

static int gnutls_hook_post_config(apr_pool_t * p, apr_pool_t * plog,
                                   apr_pool_t * ptemp,
                                   server_rec * base_server)
{
    gnutls_srvconf_rec *sc;
    server_rec *s;
    gnutls_dh_params_t dh_params;
    gnutls_rsa_params_t rsa_params;


    /* TODO: Should we regenerate these after X requests / X time ? */
//    gnutls_dh_params_init(&dh_params);
//    gnutls_dh_params_generate2(dh_params, DH_BITS);
//    gnutls_rsa_params_init(&rsa_params);
//    gnutls_rsa_params_generate2(rsa_params, RSA_BITS);

    for (s = base_server; s; s = s->next) {
        sc = (gnutls_srvconf_rec *) ap_get_module_config(s->module_config,
                                                         &gnutls_module);
        if (sc->cert_file != NULL && sc->key_file != NULL) {
            gnutls_certificate_set_x509_key_file(sc->certs, sc->cert_file,
                                                 sc->key_file,
                                                 GNUTLS_X509_FMT_PEM);
//          gnutls_certificate_set_rsa_export_params(sc->certs, rsa_params);
//          gnutls_certificate_set_dh_params(sc->certs, dh_params);
        }
        else if (sc->enabled == GNUTLS_ENABLED_TRUE) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                         "[GnuTLS] - Host '%s:%d' is missing a Cert and Key File!",
                         s->server_hostname, s->port);
        }
    }


    ap_add_version_component(p, "GnuTLS/" LIBGNUTLS_VERSION);
    return OK;
}

static const char *gnutls_hook_http_method(const request_rec * r)
{
    gnutls_srvconf_rec *sc =
        (gnutls_srvconf_rec *) ap_get_module_config(r->server->module_config,
                                                    &gnutls_module);

    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return NULL;
    }

    return "https";
}

static apr_port_t gnutls_hook_default_port(const request_rec * r)
{
    gnutls_srvconf_rec *sc =
        (gnutls_srvconf_rec *) ap_get_module_config(r->server->module_config,
                                                    &gnutls_module);

    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return 0;
    }

    return 443;
}

static int gnutls_hook_pre_connection(conn_rec * c, void *csd)
{
    gnutls_handle_t *ctxt;
    gnutls_srvconf_rec *sc =
        (gnutls_srvconf_rec *) ap_get_module_config(c->base_server->
                                                    module_config,
                                                    &gnutls_module);

    if (!(sc && (sc->enabled == GNUTLS_ENABLED_TRUE))) {
        return DECLINED;
    }

    ctxt = apr_pcalloc(c->pool, sizeof(*ctxt));

    ctxt->sc = sc;
    ctxt->status = 0;
    gnutls_init(&ctxt->session, GNUTLS_SERVER);

    gnutls_cipher_set_priority(ctxt->session, sc->ciphers);
    gnutls_compression_set_priority(ctxt->session, sc->compression);
    gnutls_kx_set_priority(ctxt->session, sc->key_exchange);
    gnutls_protocol_set_priority(ctxt->session, sc->protocol);
    gnutls_mac_set_priority(ctxt->session, sc->macs);

    gnutls_credentials_set(ctxt->session, GNUTLS_CRD_CERTIFICATE, sc->certs);
//  if(anon) {
//    gnutls_credentials_set(ctxt->session, GNUTLS_CRD_ANON, sc->anoncred);
//  }

    gnutls_certificate_server_set_request(ctxt->session, GNUTLS_CERT_IGNORE);

//    gnutls_dh_set_prime_bits(ctxt->session, DH_BITS);


    ap_set_module_config(c->conn_config, &gnutls_module, ctxt);

    gnutls_transport_set_pull_function(ctxt->session,
                                       mod_gnutls_transport_read);
    gnutls_transport_set_push_function(ctxt->session,
                                       mod_gnutls_transport_write);
    gnutls_transport_set_ptr(ctxt->session, ctxt);
    ap_add_input_filter(GNUTLS_INPUT_FILTER_NAME, ctxt, NULL, c);
    ap_add_output_filter(GNUTLS_OUTPUT_FILTER_NAME, ctxt, NULL, c);

    return OK;
}

static const char *gnutls_set_cert_file(cmd_parms * parms, void *dummy,
                                        const char *arg)
{
    gnutls_srvconf_rec *sc =
        (gnutls_srvconf_rec *) ap_get_module_config(parms->server->
                                                    module_config,
                                                    &gnutls_module);
    sc->cert_file = apr_pstrdup(parms->pool, arg);
    return NULL;
}

static const char *gnutls_set_key_file(cmd_parms * parms, void *dummy,
                                       const char *arg)
{
    gnutls_srvconf_rec *sc =
        (gnutls_srvconf_rec *) ap_get_module_config(parms->server->
                                                    module_config,
                                                    &gnutls_module);
    sc->key_file = apr_pstrdup(parms->pool, arg);
    return NULL;
}

static const char *gnutls_set_enabled(cmd_parms * parms, void *dummy,
                                      const char *arg)
{
    gnutls_srvconf_rec *sc =
        (gnutls_srvconf_rec *) ap_get_module_config(parms->server->
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
    ap_hook_pre_connection(gnutls_hook_pre_connection, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_post_config(gnutls_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_http_method(gnutls_hook_http_method, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port(gnutls_hook_default_port, NULL, NULL,
                         APR_HOOK_MIDDLE);
    ap_hook_pre_config(gnutls_hook_pre_config, NULL, NULL, APR_HOOK_MIDDLE);

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
    gnutls_srvconf_rec *sc = apr_pcalloc(p, sizeof(*sc));

    sc->enabled = GNUTLS_ENABLED_FALSE;

    gnutls_certificate_allocate_credentials(&sc->certs);
    gnutls_anon_allocate_server_credentials(&sc->anoncred);
    sc->key_file = NULL;
    sc->cert_file = NULL;

    i = 0;
    sc->ciphers[i++] = GNUTLS_CIPHER_RIJNDAEL_128_CBC;
    sc->ciphers[i++] = GNUTLS_CIPHER_ARCFOUR_128;
    sc->ciphers[i++] = GNUTLS_CIPHER_3DES_CBC;
    sc->ciphers[i++] = GNUTLS_CIPHER_ARCFOUR_40;
    sc->ciphers[i] = 0;

    i = 0;
    sc->key_exchange[i++] = GNUTLS_KX_RSA;
    sc->key_exchange[i++] = GNUTLS_KX_RSA_EXPORT;
    sc->key_exchange[i++] = GNUTLS_KX_DHE_RSA;
    sc->key_exchange[i++] = GNUTLS_KX_DHE_DSS;
    sc->key_exchange[i] = 0;

    i = 0;
    sc->macs[i++] = GNUTLS_MAC_MD5;
    sc->macs[i++] = GNUTLS_MAC_SHA;
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

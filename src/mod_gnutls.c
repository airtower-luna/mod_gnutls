/**
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
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

static void gnutls_hooks(apr_pool_t * p) {
    
    /* Try Run Post-Config Hook After mod_proxy */
    static const char * const aszPre[] = { "mod_proxy.c", NULL };
    ap_hook_post_config(mgs_hook_post_config, aszPre, NULL,APR_HOOK_REALLY_LAST); 
    /* HTTP Scheme Hook */
#if USING_2_1_RECENT
    ap_hook_http_scheme(mgs_hook_http_scheme, NULL, NULL, APR_HOOK_MIDDLE);
#else
    ap_hook_http_method(mgs_hook_http_scheme, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    /* Default Port Hook */
    ap_hook_default_port(mgs_hook_default_port,  NULL,NULL, APR_HOOK_MIDDLE);
    /* Pre-Connect Hook */
    ap_hook_pre_connection(mgs_hook_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    /* Pre-Config Hook */
    ap_hook_pre_config(mgs_hook_pre_config, NULL, NULL,
            APR_HOOK_MIDDLE);    
    /* Child-Init Hook */
    ap_hook_child_init(mgs_hook_child_init, NULL, NULL,
            APR_HOOK_MIDDLE);
    /* Authentication Hook */
    ap_hook_access_checker(mgs_hook_authz, NULL, NULL,
            APR_HOOK_REALLY_FIRST);
    /* Fixups Hook */
    ap_hook_fixups(mgs_hook_fixups, NULL, NULL, APR_HOOK_REALLY_FIRST);

    /* TODO: HTTP Upgrade Filter */
    /* ap_register_output_filter ("UPGRADE_FILTER", 
     *          ssl_io_filter_Upgrade, NULL, AP_FTYPE_PROTOCOL + 5);
     */

    /* Input Filter */
    ap_register_input_filter(GNUTLS_INPUT_FILTER_NAME,
            mgs_filter_input, NULL,AP_FTYPE_CONNECTION + 5);
    /* Output Filter */
    ap_register_output_filter(GNUTLS_OUTPUT_FILTER_NAME,
            mgs_filter_output, NULL,AP_FTYPE_CONNECTION + 5);
    
    /* mod_proxy calls these functions */
    APR_REGISTER_OPTIONAL_FN(ssl_proxy_enable);
    APR_REGISTER_OPTIONAL_FN(ssl_engine_disable);
}

int ssl_is_https(conn_rec *c) {
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) 
            ap_get_module_config(c->base_server->module_config, &gnutls_module);
    if(sc->enabled == 0 || sc->non_ssl_request == 1) {
        /* SSL/TLS Disabled or Plain HTTP Connection Detected */
        return 0;
    }
    /* Connection is Using SSL/TLS */
    return 1;
}

int ssl_engine_disable(conn_rec *c) {
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) 
            ap_get_module_config(c->base_server->module_config, &gnutls_module);
    if(sc->enabled == GNUTLS_ENABLED_FALSE) {
        return 1;
    } 
    ap_remove_input_filter(c->input_filters);
    ap_remove_input_filter(c->output_filters);
    mgs_cleanup_pre_config(c->pool);
    sc->enabled = 0;
    return 1;
}

int ssl_proxy_enable(conn_rec *c) {
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) 
            ap_get_module_config(c->base_server->module_config, &gnutls_module);
    sc->proxy_enabled = 1;
    sc->enabled = 0;
    return 1;
}

static const command_rec mgs_config_cmds[] = {
    AP_INIT_TAKE1("SSLProxyEngine", mgs_set_proxy_engine,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "Enable SSL Proxy Engine"),
    AP_INIT_TAKE1("GnuTLSClientVerify", mgs_set_client_verify,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "Set Verification Requirements of the Client Certificate"),
    AP_INIT_TAKE1("GnuTLSClientVerifyMethod", mgs_set_client_verify_method,
    NULL,
    RSRC_CONF,
    "Set Verification Method of the Client Certificate"),
    AP_INIT_TAKE1("GnuTLSClientCAFile", mgs_set_client_ca_file,
    NULL,
    RSRC_CONF,
    "Set the CA File to verify Client Certificates"),
    AP_INIT_TAKE1("GnuTLSX509CAFile", mgs_set_client_ca_file,
    NULL,
    RSRC_CONF,
    "Set the CA File to verify Client Certificates"),
    AP_INIT_TAKE1("GnuTLSPGPKeyringFile", mgs_set_keyring_file,
    NULL,
    RSRC_CONF,
    "Set the Keyring File to verify Client Certificates"),
    AP_INIT_TAKE1("GnuTLSDHFile", mgs_set_dh_file,
    NULL,
    RSRC_CONF,
    "Set the file to read Diffie Hellman parameters from"),
    AP_INIT_TAKE1("GnuTLSCertificateFile", mgs_set_cert_file,
    NULL,
    RSRC_CONF,
    "SSL Server X509 Certificate file"),
    AP_INIT_TAKE1("GnuTLSKeyFile", mgs_set_key_file,
    NULL,
    RSRC_CONF,
    "SSL Server X509 Private Key file"),
    AP_INIT_TAKE1("GnuTLSX509CertificateFile", mgs_set_cert_file,
    NULL,
    RSRC_CONF,
    "SSL Server X509 Certificate file"),
    AP_INIT_TAKE1("GnuTLSX509KeyFile", mgs_set_key_file,
    NULL,
    RSRC_CONF,
    "SSL Server X509 Private Key file"),
    AP_INIT_TAKE1("GnuTLSPGPCertificateFile", mgs_set_pgpcert_file,
    NULL,
    RSRC_CONF,
    "SSL Server PGP Certificate file"),
    AP_INIT_TAKE1("GnuTLSPGPKeyFile", mgs_set_pgpkey_file,
    NULL,
    RSRC_CONF,
    "SSL Server PGP Private key file"),
#ifdef ENABLE_SRP
    AP_INIT_TAKE1("GnuTLSSRPPasswdFile", mgs_set_srp_tpasswd_file,
    NULL,
    RSRC_CONF,
    "SSL Server SRP Password Conf file"),
    AP_INIT_TAKE1("GnuTLSSRPPasswdConfFile",
    mgs_set_srp_tpasswd_conf_file,
    NULL,
    RSRC_CONF,
    "SSL Server SRP Parameters file"),
#endif
    AP_INIT_TAKE1("GnuTLSCacheTimeout", mgs_set_cache_timeout,
    NULL,
    RSRC_CONF,
    "Cache Timeout"),
    AP_INIT_TAKE12("GnuTLSCache", mgs_set_cache,
    NULL,
    RSRC_CONF,
    "Cache Configuration"),
    AP_INIT_TAKE1("GnuTLSSessionTickets", mgs_set_tickets,
    NULL,
    RSRC_CONF,
    "Session Tickets Configuration"),
    AP_INIT_RAW_ARGS("GnuTLSPriorities", mgs_set_priorities,
    NULL,
    RSRC_CONF,
    "The priorities to enable (ciphers, Key exchange, macs, compression)."),
    AP_INIT_TAKE1("GnuTLSEnable", mgs_set_enabled,
    NULL,
    RSRC_CONF,
    "Whether this server has GnuTLS Enabled. Default: Off"),
    AP_INIT_TAKE1("GnuTLSExportCertificates",
    mgs_set_export_certificates_enabled,
    NULL,
    RSRC_CONF,
    "Whether to export PEM encoded certificates to CGIs. Default: Off"),
    { NULL },
};

module AP_MODULE_DECLARE_DATA gnutls_module = {
    STANDARD20_MODULE_STUFF,
    .create_dir_config = mgs_config_dir_create,
    .merge_dir_config = mgs_config_dir_merge,
    .create_server_config = mgs_config_server_create,
    .merge_server_config = mgs_config_server_merge,
    .cmds = mgs_config_cmds,
    .register_hooks = gnutls_hooks
};

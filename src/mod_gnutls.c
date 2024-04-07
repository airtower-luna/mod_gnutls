/*
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008, 2014 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
 *  Copyright 2015-2023 Fiona Klute
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

#include "mod_gnutls.h"
#include "gnutls_config.h"
#include "gnutls_io.h"
#include "gnutls_ocsp.h"
#include "gnutls_util.h"

#include <apr_strings.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

int ssl_engine_set(conn_rec *c,
                   ap_conf_vector_t *dir_conf __attribute__((unused)),
                   int proxy, int enable);

#define MOD_HTTP2 "mod_http2.c"
#define MOD_WATCHDOG "mod_watchdog.c"
static const char * const mod_proxy[] = { "mod_proxy.c", NULL };
static const char * const mod_http2[] = { MOD_HTTP2, NULL };
static const char * const mod_watchdog[] = { MOD_WATCHDOG, NULL };

static void gnutls_hooks(apr_pool_t * p __attribute__((unused)))
{
    /* Watchdog callbacks must be configured before post_config of
     * mod_watchdog runs, or the watchdog won't be started. Similarly,
     * our child_init hook must run before mod_watchdog's because our
     * watchdog threads are started there and need some child-specific
     * resources. */
    static const char * const post_conf_succ[] =
        { MOD_HTTP2, MOD_WATCHDOG, NULL };
    ap_hook_post_config(mgs_hook_post_config, mod_proxy, post_conf_succ,
                        APR_HOOK_MIDDLE);
    /* HTTP Scheme Hook */
    ap_hook_http_scheme(mgs_hook_http_scheme, NULL, NULL, APR_HOOK_MIDDLE);
    /* Default Port Hook */
    ap_hook_default_port(mgs_hook_default_port, NULL, NULL, APR_HOOK_MIDDLE);
    /* Pre-Connect Hook */
    ap_hook_pre_connection(mgs_hook_pre_connection, mod_http2, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_process_connection(mgs_hook_process_connection,
                               NULL, mod_http2, APR_HOOK_MIDDLE);
    /* Pre-Config Hook */
    ap_hook_pre_config(mgs_hook_pre_config, NULL, NULL,
                       APR_HOOK_MIDDLE);
    /* Child-Init Hook */
    ap_hook_child_init(mgs_hook_child_init, NULL, mod_watchdog,
                       APR_HOOK_MIDDLE);
    /* Authentication Hook */
    ap_hook_access_checker(mgs_hook_authz, NULL, NULL,
                           APR_HOOK_REALLY_FIRST);
    /* Fixups Hook */
    ap_hook_fixups(mgs_hook_fixups, NULL, NULL, APR_HOOK_REALLY_FIRST);

    /* Request hook: Check if TLS connection and request host match */
    ap_hook_post_read_request(mgs_req_vhost_check, NULL, NULL, APR_HOOK_MIDDLE);

    /* TODO: HTTP Upgrade Filter */
    /* ap_register_output_filter ("UPGRADE_FILTER",
     *          ssl_io_filter_Upgrade, NULL, AP_FTYPE_PROTOCOL + 5);
     */

    /* Input Filter */
    ap_register_input_filter(GNUTLS_INPUT_FILTER_NAME, mgs_filter_input,
                             NULL, AP_FTYPE_CONNECTION + 5);
    /* Output Filter */
    ap_register_output_filter(GNUTLS_OUTPUT_FILTER_NAME, mgs_filter_output,
                              NULL, AP_FTYPE_CONNECTION + 5);

    /* mod_proxy calls these functions */
    APR_REGISTER_OPTIONAL_FN(ssl_proxy_enable);
    APR_REGISTER_OPTIONAL_FN(ssl_engine_disable);
    APR_REGISTER_OPTIONAL_FN(ssl_engine_set);

    /* mod_rewrite calls this function to detect HTTPS */
    APR_REGISTER_OPTIONAL_FN(ssl_is_https);
    /* some modules look up TLS-related variables */
    APR_REGISTER_OPTIONAL_FN(ssl_var_lookup);
}



/**
 * Get the connection context, resolving to a master connection if
 * any.
 *
 * @param c the connection handle
 *
 * @return mod_gnutls session context, might be `NULL`
 */
mgs_handle_t* get_effective_gnutls_ctxt(conn_rec *c)
{
    mgs_handle_t *ctxt = (mgs_handle_t *)
        ap_get_module_config(c->conn_config, &gnutls_module);
    if (!(ctxt != NULL && ctxt->enabled) && (c->master != NULL))
    {
        ctxt = (mgs_handle_t *)
            ap_get_module_config(c->master->conn_config, &gnutls_module);
    }
    return ctxt;
}



/**
 * mod_rewrite calls this function to fill %{HTTPS}.
 *
 * @param c the connection to check
 * @return non-zero value if HTTPS is in use, zero if not
 */
int ssl_is_https(conn_rec *c)
{
    mgs_handle_t *ctxt = get_effective_gnutls_ctxt(c);
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(c->base_server->module_config, &gnutls_module);

    if(sc->enabled == GNUTLS_ENABLED_FALSE
       || ctxt == NULL
       || ctxt->enabled == GNUTLS_ENABLED_FALSE)
    {
        /* SSL/TLS Disabled or Plain HTTP Connection Detected */
        return 0;
    }
    /* Connection is Using SSL/TLS */
    return 1;
}



/**
 * Return variables describing the current TLS session (if any).
 *
 * mod_ssl doc for this function: "This function must remain safe to
 * use for a non-SSL connection." mod_http2 uses it to check if an
 * acceptable TLS session is used.
 */
char* ssl_var_lookup(apr_pool_t *p, server_rec *s __attribute__((unused)),
                     conn_rec *c, request_rec *r, char *var)
{
    /*
     * When no pool is given try to find one
     */
    if (p == NULL) {
        if (r != NULL)
            p = r->pool;
        else if (c != NULL)
            p = c->pool;
        else
            return NULL;
    }

    if (strcmp(var, "HTTPS") == 0)
    {
        if (c != NULL && ssl_is_https(c))
            return "on";
        else
            return "off";
    }

    mgs_handle_t *ctxt = get_effective_gnutls_ctxt(c);

    /* TLS parameters are empty if there is no session */
    if (ctxt == NULL || ctxt->c == NULL || ctxt->session == NULL)
        return NULL;

    if (strcmp(var, "SSL_PROTOCOL") == 0)
        return apr_pstrdup(p, gnutls_protocol_get_name(gnutls_protocol_get_version(ctxt->session)));

    if (strcmp(var, "SSL_CIPHER") == 0)
        return apr_pstrdup(p, gnutls_cipher_suite_get_name(gnutls_kx_get(ctxt->session),
                                                           gnutls_cipher_get(ctxt->session),
                                                           gnutls_mac_get(ctxt->session)));

    /* mod_ssl supports a LOT more variables */
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, c,
                  "unsupported variable requested: '%s'",
                  var);

    return NULL;
}



/**
 * In Apache versions from 2.4.33 mod_proxy uses this function to set
 * up its client connections. Note that mod_gnutls does not (yet)
 * implement per directory configuration for such connections.
 *
 * @param c the connection
 * @param dir_conf per directory configuration, unused for now
 * @param proxy Is this a proxy connection?
 * @param enable Should TLS be enabled on this connection?
 *
 * @return `true` (1) if successful, `false` (0) otherwise
 */
int ssl_engine_set(conn_rec *c,
                   ap_conf_vector_t *dir_conf __attribute__((unused)),
                   int proxy, int enable)
{
    mgs_handle_t *ctxt = init_gnutls_ctxt(c);

    /* If TLS proxy has been requested, check if support is enabled
     * for the server */
    if (proxy && (ctxt->sc->proxy_enabled != GNUTLS_ENABLED_TRUE))
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "%s: mod_proxy requested TLS proxy, but not enabled "
                      "for %s:%d", __func__,
                      ctxt->c->base_server->server_hostname,
                      ctxt->c->base_server->addrs->host_port);
        return 0;
    }

    if (proxy)
        ctxt->is_proxy = GNUTLS_ENABLED_TRUE;
    else
        ctxt->is_proxy = GNUTLS_ENABLED_FALSE;

    if (enable)
        ctxt->enabled = GNUTLS_ENABLED_TRUE;
    else
        ctxt->enabled = GNUTLS_ENABLED_FALSE;

    return 1;
}

int ssl_engine_disable(conn_rec *c)
{
    return ssl_engine_set(c, NULL, 0, 0);
}

int ssl_proxy_enable(conn_rec *c)
{
    return ssl_engine_set(c, NULL, 1, 1);
}

static const command_rec mgs_config_cmds[] = {
    AP_INIT_FLAG("GnuTLSProxyEngine", mgs_set_proxy_engine,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "Enable TLS Proxy Engine"),
    AP_INIT_TAKE1("GnuTLSP11Module", mgs_set_p11_module,
    NULL,
    RSRC_CONF,
    "Load this specific PKCS #11 provider library"),
    AP_INIT_RAW_ARGS("GnuTLSPIN", mgs_set_pin,
    NULL,
    RSRC_CONF,
    "The PIN to use in case of encrypted keys or PKCS #11 tokens."),
    AP_INIT_RAW_ARGS("GnuTLSSRKPIN", mgs_set_srk_pin,
    NULL,
    RSRC_CONF,
    "The SRK PIN to use in case of TPM keys."),
    AP_INIT_TAKE1("GnuTLSClientVerify", mgs_set_client_verify,
    NULL,
    RSRC_CONF | OR_AUTHCFG,
    "Set Verification Requirements of the Client Certificate"),
    AP_INIT_TAKE1("GnuTLSClientCAFile", mgs_set_client_ca_file,
    NULL,
    RSRC_CONF,
    "Set the CA File to verify Client Certificates"),
    AP_INIT_TAKE1("GnuTLSX509CAFile", mgs_set_client_ca_file,
    NULL,
    RSRC_CONF,
    "Set the CA File to verify Client Certificates"),
    AP_INIT_TAKE1("GnuTLSDHFile", mgs_set_dh_file,
    NULL,
    RSRC_CONF,
    "Set the file to read Diffie Hellman parameters from"),
    AP_INIT_TAKE1("GnuTLSCertificateFile", mgs_set_cert_file,
    NULL,
    RSRC_CONF,
    "TLS Server X509 Certificate file"),
    AP_INIT_TAKE1("GnuTLSKeyFile", mgs_set_key_file,
    NULL,
    RSRC_CONF,
    "TLS Server X509 Private Key file"),
    AP_INIT_TAKE1("GnuTLSX509CertificateFile", mgs_set_cert_file,
    NULL,
    RSRC_CONF,
    "TLS Server X509 Certificate file"),
    AP_INIT_TAKE1("GnuTLSX509KeyFile", mgs_set_key_file,
    NULL,
    RSRC_CONF,
    "TLS Server X509 Private Key file"),
    AP_INIT_TAKE1("GnuTLSCacheTimeout", mgs_set_timeout,
    NULL,
    RSRC_CONF,
    "Cache Timeout"),
    AP_INIT_TAKE12("GnuTLSCache", mgs_set_cache,
    NULL,
    RSRC_CONF,
    "Session Cache Configuration"),
    AP_INIT_FLAG("GnuTLSSessionTickets", mgs_set_tickets,
    NULL,
    RSRC_CONF,
    "Session Tickets Configuration"),
    AP_INIT_RAW_ARGS("GnuTLSPriorities", mgs_set_priorities,
    NULL,
    RSRC_CONF,
    "The priorities to enable (ciphers, Key exchange, macs, compression)."),
    AP_INIT_FLAG("GnuTLSEnable", mgs_set_enabled,
    NULL,
    RSRC_CONF,
    "Whether this server has GnuTLS Enabled. Default: Off"),
    AP_INIT_TAKE1("GnuTLSExportCertificates",
    mgs_set_export_certificates_size,
    NULL,
    RSRC_CONF,
    "Max size to export PEM encoded certificates to CGIs (or off to disable). Default: off"),
    AP_INIT_TAKE1("GnuTLSProxyKeyFile", mgs_store_cred_path,
    NULL,
    RSRC_CONF,
    "X509 client private file for proxy connections"),
    AP_INIT_TAKE1("GnuTLSProxyCertificateFile", mgs_store_cred_path,
    NULL,
    RSRC_CONF,
    "X509 client certificate file for proxy connections"),
    AP_INIT_TAKE1("GnuTLSProxyCAFile", mgs_store_cred_path,
    NULL,
    RSRC_CONF,
    "X509 trusted CA file for proxy connections"),
    AP_INIT_TAKE1("GnuTLSProxyCRLFile", mgs_store_cred_path,
    NULL,
    RSRC_CONF,
    "X509 CRL file for proxy connections"),
    AP_INIT_RAW_ARGS("GnuTLSProxyPriorities", mgs_set_priorities,
    NULL,
    RSRC_CONF,
    "The priorities to enable for proxy connections (ciphers, key exchange, "
    "MACs, compression)."),
    AP_INIT_FLAG("GnuTLSOCSPStapling", mgs_ocsp_stapling_enable,
                 NULL, RSRC_CONF,
                 "Enable OCSP stapling"),
    AP_INIT_FLAG("GnuTLSOCSPAutoRefresh", mgs_set_ocsp_auto_refresh,
                 NULL, RSRC_CONF,
                 "Regularly refresh cached OCSP response independent "
                 "of TLS handshakes?"),
    AP_INIT_TAKE12("GnuTLSOCSPCache", mgs_set_cache,
                   NULL,
                   RSRC_CONF,
                  "OCSP Cache Configuration"),
    AP_INIT_FLAG("GnuTLSOCSPCheckNonce", mgs_set_ocsp_check_nonce,
                 NULL, RSRC_CONF,
                 "Check nonce in OCSP responses?"),
    AP_INIT_TAKE_ARGV("GnuTLSOCSPResponseFile", mgs_store_ocsp_response_path,
                  NULL, RSRC_CONF,
                  "Read OCSP responses for stapling from these files instead "
                  "of sending a request over HTTP. Files must be listed in "
                  "the same order as listed in GnuTLSX509CertificateFile, "
                  "and must be updated externally. Use the empty string "
                  "(\"\") to skip a certificate in the list."),
    AP_INIT_TAKE1("GnuTLSOCSPCacheTimeout", mgs_set_timeout,
                  NULL, RSRC_CONF,
                  "Cache timeout for OCSP responses"),
    AP_INIT_TAKE1("GnuTLSOCSPFailureTimeout", mgs_set_timeout,
                  NULL, RSRC_CONF,
                  "Wait this many seconds before retrying a failed OCSP "
                  "request"),
    AP_INIT_TAKE1("GnuTLSOCSPFuzzTime", mgs_set_timeout,
                  NULL, RSRC_CONF,
                  "Update cached OCSP response up to this many seconds "
                  "before it expires, if GnuTLSOCSPAutoRefresh is enabled."),
    AP_INIT_TAKE1("GnuTLSOCSPSocketTimeout", mgs_set_timeout,
                  NULL, RSRC_CONF,
                  "Socket timeout for OCSP requests"),
    { 0 },
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

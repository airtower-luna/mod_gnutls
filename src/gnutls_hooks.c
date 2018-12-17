/*
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008, 2014 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
 *  Copyright 2013-2014 Daniel Kahn Gillmor
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

#include "mod_gnutls.h"
#include "gnutls_cache.h"
#include "gnutls_config.h"
#include "gnutls_ocsp.h"
#include "gnutls_sni.h"
#include "gnutls_util.h"
#include "gnutls_watchdog.h"

#include "http_vhost.h"
#include "ap_mpm.h"
#include <mod_status.h>
#include <util_mutex.h>
#include <apr_escape.h>
/* This provides strcmp and related functions */
#define APR_WANT_STRFUNC
#include <apr_want.h>

#ifdef ENABLE_MSVA
#include <msv/msv.h>
#endif

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

#if MOD_GNUTLS_DEBUG
static apr_file_t *debug_log_fp;
#endif

#define IS_PROXY_STR(c) \
    ((c->is_proxy == GNUTLS_ENABLED_TRUE) ? "proxy " : "")

/** Key to encrypt session tickets. Must be kept secret. This key is
 * generated in the `pre_config` hook and thus constant across
 * forks. The problem with this approach is that it does not support
 * regular key rotation. */
static gnutls_datum_t session_ticket_key = {NULL, 0};



static int mgs_cert_verify(request_rec * r, mgs_handle_t * ctxt);
/** use side==0 for server and side==1 for client */
static void mgs_add_common_cert_vars(request_rec * r, gnutls_x509_crt_t cert, int side, size_t export_cert_size);
mgs_srvconf_rec* mgs_find_sni_server(mgs_handle_t *ctxt);
static int mgs_status_hook(request_rec *r, int flags);
#ifdef ENABLE_MSVA
static const char* mgs_x509_construct_uid(request_rec * pool, gnutls_x509_crt_t cert);
#endif
static int load_proxy_x509_credentials(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s)
    __attribute__((nonnull));

/* Pool Cleanup Function */
apr_status_t mgs_cleanup_pre_config(void *data __attribute__((unused)))
{
    /* Free session ticket master key */
#if GNUTLS_VERSION_NUMBER >= 0x030400
    gnutls_memset(session_ticket_key.data, 0, session_ticket_key.size);
#endif
    gnutls_free(session_ticket_key.data);
    session_ticket_key.data = NULL;
    session_ticket_key.size = 0;

    /* Deinit default priority setting */
    mgs_default_priority_deinit();
    return APR_SUCCESS;
}

/* Logging Function for Maintainers */
#if MOD_GNUTLS_DEBUG
static void gnutls_debug_log_all(int level, const char *str) {
    apr_file_printf(debug_log_fp, "<%d> %s", level, str);
}
#define _gnutls_log apr_file_printf
#else
#define _gnutls_log(...)
#endif

static const char* mgs_readable_cvm(mgs_client_verification_method_e m) {
    switch(m) {
    case mgs_cvm_unset:
        return "unset";
    case mgs_cvm_cartel:
        return "cartel";
    case mgs_cvm_msva:
        return "msva";
    }
    return "unknown";
}

/* Pre-Configuration HOOK: Runs First */
int mgs_hook_pre_config(apr_pool_t * pconf, apr_pool_t * plog, apr_pool_t * ptemp __attribute__((unused))) {

/* Maintainer Logging */
#if MOD_GNUTLS_DEBUG
    apr_file_open(&debug_log_fp, "/tmp/gnutls_debug", APR_APPEND | APR_WRITE | APR_CREATE, APR_OS_DEFAULT, pconf);
    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    gnutls_global_set_log_level(9);
    gnutls_global_set_log_function(gnutls_debug_log_all);
    _gnutls_log(debug_log_fp, "gnutls: %s\n", gnutls_check_version(NULL));
#endif

    int ret;

	/* Check for required GnuTLS Library Version */
    if (gnutls_check_version(LIBGNUTLS_VERSION) == NULL) {
		ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, plog, "gnutls_check_version() failed. Required: "
					"gnutls-%s Found: gnutls-%s", LIBGNUTLS_VERSION, gnutls_check_version(NULL));
        return DONE;
    }

	/* Generate a Session Key */
    ret = gnutls_session_ticket_key_generate(&session_ticket_key);
    if (ret < 0) {
		ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, plog, "gnutls_session_ticket_key_generate: %s", gnutls_strerror(ret));
		return DONE;
    }

    /* Initialize default priority setting */
    ret = mgs_default_priority_init();
    if (ret < 0)
    {
        ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, plog,
                      "gnutls_priority_init failed for default '%s': %s (%d)",
                      MGS_DEFAULT_PRIORITY, gnutls_strerror(ret), ret);
        return DONE;
    }

    AP_OPTIONAL_HOOK(status_hook, mgs_status_hook, NULL, NULL, APR_HOOK_MIDDLE);

    ap_mutex_register(pconf, MGS_CACHE_MUTEX_NAME, NULL, APR_LOCK_DEFAULT, 0);
    ap_mutex_register(pconf, MGS_OCSP_MUTEX_NAME, NULL, APR_LOCK_DEFAULT, 0);
    ap_mutex_register(pconf, MGS_OCSP_CACHE_MUTEX_NAME, NULL,
                      APR_LOCK_DEFAULT, 0);

    /* Register a pool clean-up function */
    apr_pool_cleanup_register(pconf, NULL, mgs_cleanup_pre_config, apr_pool_cleanup_null);

    return OK;
}



/**
 * Get the list of available protocols for this connection and add it
 * to the GnuTLS session. Must run before the client hello function.
 */
static void prepare_alpn_proposals(mgs_handle_t *ctxt)
{
    /* Check if any protocol upgrades are available
     *
     * The "report_all" parameter to ap_get_protocol_upgrades() is 0
     * (report only more preferable protocols) because setting it to 1
     * doesn't actually report ALL protocols, but only all except the
     * current one. This way we can at least list the current one as
     * available by appending it without potentially negotiating a
     * less preferred protocol. */
    const apr_array_header_t *pupgrades = NULL;
    apr_status_t ret =
        ap_get_protocol_upgrades(ctxt->c, NULL, ctxt->sc->s,
                                 /*report_all*/ 0, &pupgrades);
    if (ret != APR_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, ctxt->c,
                      "%s: ap_get_protocol_upgrades() failed, "
                      "cannot configure ALPN!", __func__);
        return;
    }

    if (pupgrades == NULL || pupgrades->nelts == 0)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, ctxt->c,
                      "%s: No protocol upgrades available.", __func__);
        return;
    }

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctxt->c,
                  "%s: Found %d protocol upgrade(s) for ALPN: %s",
                  __func__, pupgrades->nelts,
                  apr_array_pstrcat(ctxt->c->pool, pupgrades, ','));
    gnutls_datum_t *alpn_protos =
        apr_palloc(ctxt->c->pool,
                   (pupgrades->nelts + 1) * sizeof(gnutls_datum_t));
    for (int i = 0; i < pupgrades->nelts; i++)
    {
        alpn_protos[i].data = (void *) APR_ARRAY_IDX(pupgrades, i, char *);
        alpn_protos[i].size =
            strnlen(APR_ARRAY_IDX(pupgrades, i, char *),
                    pupgrades->elt_size);
    }

    /* Add the current (default) protocol at the end of the list */
    alpn_protos[pupgrades->nelts].data =
        (void*) apr_pstrdup(ctxt->c->pool, ap_get_protocol(ctxt->c));
    alpn_protos[pupgrades->nelts].size =
        strlen((char*) alpn_protos[pupgrades->nelts].data);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, ctxt->c,
                  "%s: Adding current protocol %s to ALPN set.",
                  __func__, alpn_protos[pupgrades->nelts].data);

    gnutls_alpn_set_protocols(ctxt->session,
                              alpn_protos,
                              pupgrades->nelts,
                              GNUTLS_ALPN_SERVER_PRECEDENCE);
}



/**
 * Check if ALPN selected any protocol upgrade, try to switch if so.
 */
static int process_alpn_result(mgs_handle_t *ctxt)
{
    int ret = 0;
    gnutls_datum_t alpn_proto;
    ret = gnutls_alpn_get_selected_protocol(ctxt->session, &alpn_proto);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, ctxt->c,
                      "%s: No ALPN result: %s (%d)",
                      __func__, gnutls_strerror(ret), ret);
        return GNUTLS_E_SUCCESS;
    }

    apr_array_header_t *client_protos =
        apr_array_make(ctxt->c->pool, 1, sizeof(char *));
    /* apr_pstrndup to ensure that the protocol is null terminated */
    APR_ARRAY_PUSH(client_protos, char *) =
        apr_pstrndup(ctxt->c->pool, (char*) alpn_proto.data, alpn_proto.size);
    const char *selected =
        ap_select_protocol(ctxt->c, NULL, ctxt->sc->s, client_protos);

    /* ap_select_protocol() will return NULL if none of the ALPN
     * proposals matched. GnuTLS negotiated alpn_proto based on the
     * list provided by the server, but the vhost might have changed
     * based on SNI. Apache seems to adjust the proposal list to avoid
     * such issues though.
     *
     * GnuTLS will return a fatal "no_application_protocol" alert as
     * required by RFC 7301 if the post client hello function returns
     * GNUTLS_E_NO_APPLICATION_PROTOCOL. */
    if (!selected)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "%s: ap_select_protocol() returned NULL! Please "
                      "make sure any overlapping vhosts have the same "
                      "protocols available.",
                      __func__);
        return GNUTLS_E_NO_APPLICATION_PROTOCOL;
    }

    if (strcmp(selected, ap_get_protocol(ctxt->c)) == 0)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, ctxt->c,
                      "%s: Already using protocol '%s', nothing to do.",
                      __func__, selected);
        return GNUTLS_E_SUCCESS;
    }

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                  "%s: Switching protocol to '%s' based on ALPN.",
                  __func__, selected);
    apr_status_t status = ap_switch_protocol(ctxt->c, NULL,
                                             ctxt->sc->s,
                                             selected);
    if (status != APR_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, ctxt->c,
                      "%s: Protocol switch to '%s' failed!",
                      __func__, selected);
        return GNUTLS_E_NO_APPLICATION_PROTOCOL;
    }
    /* ALPN done! */
    return GNUTLS_E_SUCCESS;
}



/**
 * (Re-)Load credentials and priorities for the connection. This is
 * meant to be called after virtual host selection in the pre or post
 * client hello hook.
 */
static int reload_session_credentials(mgs_handle_t *ctxt)
{
    int ret = 0;

    gnutls_certificate_server_set_request(ctxt->session,
                                          ctxt->sc->client_verify_mode);

    /* Set x509 credentials */
    gnutls_credentials_set(ctxt->session,
                           GNUTLS_CRD_CERTIFICATE, ctxt->sc->certs);
    /* Set Anon credentials */
    gnutls_credentials_set(ctxt->session, GNUTLS_CRD_ANON,
                           ctxt->sc->anon_creds);

#ifdef ENABLE_SRP
	/* Set SRP credentials */
    if (ctxt->sc->srp_tpasswd_conf_file != NULL && ctxt->sc->srp_tpasswd_file != NULL) {
        gnutls_credentials_set(ctxt->session, GNUTLS_CRD_SRP,
                               ctxt->sc->srp_creds);
    }
#endif

    /* Enable session tickets */
    if (session_ticket_key.data != NULL &&
        ctxt->sc->tickets == GNUTLS_ENABLED_TRUE)
    {
        ret = gnutls_session_ticket_enable_server(ctxt->session, &session_ticket_key);
        if (ret != GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                          "gnutls_session_ticket_enable_server failed: %s (%d)",
                          gnutls_strerror(ret), ret);
    }

    /* Update the priorities - to avoid negotiating a ciphersuite that is not
     * enabled on this virtual server. Note that here we ignore the version
     * negotiation. */
    ret = gnutls_priority_set(ctxt->session, ctxt->sc->priorities);

    return ret;
}



/**
 * Post client hello hook function for GnuTLS. This function has two
 * purposes: Firstly, it acts as a fallback for early_sni_hook(), by
 * parsing SNI and selecting a virtual host based on it if
 * necessary. Secondly, it calls ALPN processing.
 *
 * @param session the TLS session
 *
 * @return zero or a GnuTLS error code, as required by GnuTLS hook
 * definition
 */
static int post_client_hello_hook(gnutls_session_t session)
{
    int ret = 0;
    mgs_handle_t *ctxt = gnutls_session_get_ptr(session);

    /* If ctxt->sni_name is set at this point the early_sni_hook()
     * function ran, found an SNI server name, selected a virtual
     * host, and set up credentials, so we don't need to do that
     * again. Otherwise try again, to cover GnuTLS versions < 3.6.3
     * and pick up future extensions to gnutls_server_name_get(). */
    if (ctxt->sni_name == NULL)
    {
        /* try to find a virtual host */
        mgs_srvconf_rec *tsc = mgs_find_sni_server(ctxt);
        if (tsc != NULL)
        {
            /* Found a TLS vhost based on the SNI, configure the
             * connection context. */
            ctxt->sc = tsc;
        }

        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, ctxt->c,
                      "%s: Loading credentials in post client hello hook",
                      __func__);
        reload_session_credentials(ctxt);
    }

    ret = process_alpn_result(ctxt);
    if (ret != GNUTLS_E_SUCCESS)
        return ret;

    /* actually it shouldn't fail since we have checked at startup */
    return ret;
}

static int cert_retrieve_fn(gnutls_session_t session,
                            const gnutls_datum_t * req_ca_rdn __attribute__((unused)),
                            int nreqs __attribute__((unused)),
                            const gnutls_pk_algorithm_t * pk_algos __attribute__((unused)),
                            int pk_algos_length __attribute__((unused)),
                            gnutls_pcert_st **pcerts,
                            unsigned int *pcert_length,
                            gnutls_privkey_t *privkey)
{
    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);

    mgs_handle_t *ctxt;

    if (session == NULL) {
		// ERROR INVALID SESSION
        return -1;
    }

    ctxt = gnutls_transport_get_ptr(session);

    if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509) {
		// X509 CERTIFICATE
        *pcerts = ctxt->sc->certs_x509_chain;
        *pcert_length = ctxt->sc->certs_x509_chain_num;
        *privkey = ctxt->sc->privkey_x509;
        return 0;
    } else {
		// UNKNOWN CERTIFICATE
	    return -1;
	}
}



#if GNUTLS_VERSION_NUMBER >= 0x030506
#define HAVE_KNOWN_DH_GROUPS 1
#endif
#ifdef HAVE_KNOWN_DH_GROUPS
/**
 * Try to estimate a GnuTLS security parameter based on the given
 * private key. Any errors are logged.
 *
 * @param s The `server_rec` to use for logging
 *
 * @param key The private key to use
 *
 * @return `gnutls_sec_param_t` as returned by
 * `gnutls_pk_bits_to_sec_param` for the key properties, or
 * GNUTLS_SEC_PARAM_UNKNOWN in case of error
 */
static gnutls_sec_param_t sec_param_from_privkey(server_rec *server,
                                                 gnutls_privkey_t key)
{
    unsigned int bits = 0;
    int pk_algo = gnutls_privkey_get_pk_algorithm(key, &bits);
    if (pk_algo < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, server,
                     "%s: Could not get private key parameters: %s (%d)",
                     __func__, gnutls_strerror(pk_algo), pk_algo);
        return GNUTLS_SEC_PARAM_UNKNOWN;
    }
    return gnutls_pk_bits_to_sec_param(pk_algo, bits);
}
#else
/** ffdhe2048 DH group as defined in RFC 7919, Appendix A.1. This is
 * the default DH group if mod_gnutls is compiled agains a GnuTLS
 * version that does not provide known DH groups based on security
 * parameters (before 3.5.6). */
static const char FFDHE2048_PKCS3[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBDAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz\n"
    "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a\n"
    "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7\n"
    "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi\n"
    "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD\n"
    "ssbzSibBsu/6iGtCOGEoXJf//////////wIBAgICAQA=\n"
    "-----END DH PARAMETERS-----\n";
const gnutls_datum_t default_dh_params = {
    (void *) FFDHE2048_PKCS3,
    sizeof(FFDHE2048_PKCS3)
};
#endif



/**
 * Configure the default DH groups to use for the given server. When
 * compiled against GnuTLS version 3.5.6 or newer the known DH group
 * matching the GnuTLS security parameter estimated from the private
 * key is used. Otherwise the ffdhe2048 DH group as defined in RFC
 * 7919, Appendix A.1 is the default.
 *
 * @param server the host to configure
 *
 * @return `OK` on success, `HTTP_UNAUTHORIZED` otherwise
 */
static int set_default_dh_param(server_rec *server)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(server->module_config, &gnutls_module);

#ifdef HAVE_KNOWN_DH_GROUPS
    gnutls_sec_param_t seclevel = GNUTLS_SEC_PARAM_UNKNOWN;
    if (sc->privkey_x509)
    {
        seclevel = sec_param_from_privkey(server, sc->privkey_x509);
        ap_log_error(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, server,
                     "%s: GnuTLS security param estimated based on "
                     "private key '%s': %s",
                     __func__, sc->x509_key_file,
                     gnutls_sec_param_get_name(seclevel));
    }

    if (seclevel == GNUTLS_SEC_PARAM_UNKNOWN)
        seclevel = GNUTLS_SEC_PARAM_MEDIUM;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, server,
                 "%s: Setting DH params for security level '%s'.",
                 __func__, gnutls_sec_param_get_name(seclevel));

    int ret = gnutls_certificate_set_known_dh_params(sc->certs, seclevel);
    if (ret < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, APR_EGENERAL, server,
                     "%s: setting known DH params failed: %s (%d)",
                     __func__, gnutls_strerror(ret), ret);
        return HTTP_UNAUTHORIZED;
    }
    ret = gnutls_anon_set_server_known_dh_params(sc->anon_creds, seclevel);
    if (ret < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, APR_EGENERAL, server,
                     "%s: setting known DH params failed: %s (%d)",
                     __func__, gnutls_strerror(ret), ret);
        return HTTP_UNAUTHORIZED;
    }
#else
    int ret = gnutls_dh_params_init(&sc->dh_params);
    if (ret < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, server,
                     "%s: Failed to initialize DH params structure: "
                     "%s (%d)", __func__, gnutls_strerror(ret), ret);
        return HTTP_UNAUTHORIZED;
    }
    ret = gnutls_dh_params_import_pkcs3(sc->dh_params, &default_dh_params,
                                        GNUTLS_X509_FMT_PEM);
    if (ret < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, server,
                     "%s: Failed to import default DH params: %s (%d)",
                     __func__, gnutls_strerror(ret), ret);
        return HTTP_UNAUTHORIZED;
    }

    gnutls_certificate_set_dh_params(sc->certs, sc->dh_params);
    gnutls_anon_set_server_dh_params(sc->anon_creds, sc->dh_params);
#endif

    return OK;
}



/**
 * Post config hook.
 *
 * Must return OK or DECLINED on success, something else on
 * error. These codes are defined in Apache httpd.h along with the
 * HTTP status codes, so I'm going to use HTTP error codes both for
 * fun (and to avoid conflicts).
 */
int mgs_hook_post_config(apr_pool_t *pconf,
                         apr_pool_t *plog __attribute__((unused)),
                         apr_pool_t *ptemp,
                         server_rec *base_server)
{
    int rv;
    server_rec *s;
    mgs_srvconf_rec *sc;
    mgs_srvconf_rec *sc_base;
    void *data = NULL;
    const char *userdata_key = "mgs_init";

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);

    apr_pool_userdata_get(&data, userdata_key, base_server->process->pool);
    if (data == NULL) {
        apr_pool_userdata_set((const void *) 1, userdata_key, apr_pool_cleanup_null, base_server->process->pool);
    }

    s = base_server;
    sc_base = (mgs_srvconf_rec *) ap_get_module_config(s->module_config, &gnutls_module);


    rv = mgs_cache_post_config(pconf, ptemp, s, sc_base);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, s,
                     "Post config for cache failed.");
        return HTTP_INSUFFICIENT_STORAGE;
    }

    if (sc_base->ocsp_mutex == NULL)
    {
        rv = ap_global_mutex_create(&sc_base->ocsp_mutex, NULL,
                                    MGS_OCSP_MUTEX_NAME, NULL,
                                    base_server, pconf, 0);
        if (rv != APR_SUCCESS)
            return rv;
    }

    /* If GnuTLSP11Module is set, load the listed PKCS #11
     * modules. Otherwise system defaults will be used. */
    if (sc_base->p11_modules != NULL)
    {
        rv = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);
        if (rv < 0)
        {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "GnuTLS: Initializing PKCS #11 "
                         "failed: %s (%d).",
                         gnutls_strerror(rv), rv);
        }
        else
        {
            for (int i = 0; i < sc_base->p11_modules->nelts; i++)
            {
                char *p11_module =
                    APR_ARRAY_IDX(sc_base->p11_modules, i, char *);
                rv = gnutls_pkcs11_add_provider(p11_module, NULL);
                if (rv != GNUTLS_E_SUCCESS)
                    ap_log_error(APLOG_MARK, APLOG_STARTUP, APR_EGENERAL, s,
                                 "GnuTLS: Loading PKCS #11 provider module %s "
                                 "failed: %s (%d).",
                                 p11_module, gnutls_strerror(rv), rv);
                else
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                                 "%s: PKCS #11 provider module %s loaded.",
                                 __func__, p11_module);
            }
        }
    }

    sc_base->singleton_wd =
        mgs_new_singleton_watchdog(base_server, MGS_SINGLETON_WATCHDOG, pconf);

    for (s = base_server; s; s = s->next)
    {
        sc = (mgs_srvconf_rec *) ap_get_module_config(s->module_config, &gnutls_module);
        sc->s = s;
        sc->cache_enable = sc_base->cache_enable;
        sc->cache = sc_base->cache;
        if (sc->cache_timeout == MGS_TIMEOUT_UNSET)
            sc->cache_timeout = sc_base->cache_timeout;
        sc->ocsp_cache = sc_base->ocsp_cache;

        sc->singleton_wd = sc_base->singleton_wd;

        /* defaults for unset values: */
        if (sc->enabled == GNUTLS_ENABLED_UNSET)
            sc->enabled = GNUTLS_ENABLED_FALSE;
        if (sc->tickets == GNUTLS_ENABLED_UNSET)
        {
            /* GnuTLS 3.6.4 introduced automatic master key rotation */
            if (gnutls_check_version_numeric(3, 6, 4))
                sc->tickets = GNUTLS_ENABLED_TRUE;
            else
                sc->tickets = GNUTLS_ENABLED_FALSE;
        }
        if (sc->export_certificates_size < 0)
            sc->export_certificates_size = 0;
        if (sc->client_verify_mode == -1)
            sc->client_verify_mode = GNUTLS_CERT_IGNORE;
        if (sc->client_verify_method == mgs_cvm_unset)
            sc->client_verify_method = mgs_cvm_cartel;

        // TODO: None of the stuff below needs to be done if
        // sc->enabled == GNUTLS_ENABLED_FALSE, we could just continue
        // to the next host.

        /* Load certificates and stuff (includes parsing priority) */
        rv = mgs_load_files(pconf, ptemp, s);
        if (rv != 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "%s: Loading credentials failed!", __func__);
            return HTTP_NOT_FOUND;
        }

        sc->ocsp_mutex = sc_base->ocsp_mutex;
        /* init OCSP configuration unless explicitly disabled */
        if (sc->enabled && sc->ocsp_staple != GNUTLS_ENABLED_FALSE)
        {
            const char *err = mgs_ocsp_configure_stapling(pconf, ptemp, s);
            if (err != NULL)
            {
                /* If OCSP stapling is enabled only by default ignore
                 * error and disable stapling */
                if (sc->ocsp_staple == GNUTLS_ENABLED_UNSET)
                {
                    ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s,
                                 "Cannnot enable OCSP stapling for "
                                 "host '%s:%d': %s",
                                 s->server_hostname, s->addrs->host_port, err);
                    sc->ocsp_staple = GNUTLS_ENABLED_FALSE;
                }
                /* If OCSP stapling is explicitly enabled this is a
                 * critical error. */
                else
                {
                    ap_log_error(APLOG_MARK, APLOG_STARTUP, APR_EINVAL, s,
                                 "OCSP stapling configuration failed for "
                                 "host '%s:%d': %s",
                                 s->server_hostname, s->addrs->host_port, err);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            else
            {
                /* Might already be set */
                sc->ocsp_staple = GNUTLS_ENABLED_TRUE;
                /* Set up stapling */
                rv = mgs_ocsp_enable_stapling(pconf, ptemp, s);
                if (rv != OK && rv != DECLINED)
                    return rv;
            }
        }

        /* Check if the priorities have been set */
        if (sc->priorities == NULL && sc->enabled == GNUTLS_ENABLED_TRUE) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "No GnuTLSPriorities directive for host '%s:%d', "
                         "using default '%s'.",
                         s->server_hostname, s->addrs->host_port,
                         MGS_DEFAULT_PRIORITY);
            sc->priorities = mgs_get_default_prio();
        }

        /* Set host DH params from user configuration or defaults */
        if (sc->dh_params != NULL) {
            gnutls_certificate_set_dh_params(sc->certs, sc->dh_params);
            gnutls_anon_set_server_dh_params(sc->anon_creds, sc->dh_params);
        } else {
            rv = set_default_dh_param(s);
            if (rv != OK)
                return rv;
        }

        /* The call after this comment is a workaround for bug in
         * gnutls_certificate_set_retrieve_function2 that ignores
         * supported certificate types. Should be fixed in GnuTLS
         * 3.3.12.
         *
         * Details:
         * https://lists.gnupg.org/pipermail/gnutls-devel/2015-January/007377.html
         * Workaround from:
         * https://github.com/vanrein/tlspool/commit/4938102d3d1b086491d147e6c8e4e2a02825fc12 */
#if GNUTLS_VERSION_NUMBER < 0x030312
        gnutls_certificate_set_retrieve_function(sc->certs, (void *) exit);
#endif

        gnutls_certificate_set_retrieve_function2(sc->certs, cert_retrieve_fn);

        if ((sc->certs_x509_chain == NULL || sc->certs_x509_chain_num < 1) &&
            sc->enabled == GNUTLS_ENABLED_TRUE) {
			ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
						"GnuTLS: Host '%s:%d' is missing a Certificate File!",
						s->server_hostname, s->addrs->host_port);
            return HTTP_UNAUTHORIZED;
        }
        if (sc->enabled == GNUTLS_ENABLED_TRUE &&
            (sc->certs_x509_chain_num > 0 && sc->privkey_x509 == NULL))
        {
			ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
						"GnuTLS: Host '%s:%d' is missing a Private Key File!",
						s->server_hostname, s->addrs->host_port);
            return HTTP_UNAUTHORIZED;
        }

        if (sc->enabled == GNUTLS_ENABLED_TRUE
            && sc->proxy_enabled == GNUTLS_ENABLED_TRUE
            && load_proxy_x509_credentials(pconf, ptemp, s) != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "%s: loading proxy credentials for host "
                         "'%s:%d' failed, exiting!",
                         __func__, s->server_hostname, s->addrs->host_port);
            return HTTP_PROXY_AUTHENTICATION_REQUIRED;
        }
    }


    ap_add_version_component(pconf, "mod_gnutls/" MOD_GNUTLS_VERSION);

    {
        const char* libvers = gnutls_check_version(NULL);
        char* gnutls_version = NULL;
        if(libvers && (gnutls_version = apr_psprintf(pconf, "GnuTLS/%s", libvers))) {
            ap_add_version_component(pconf, gnutls_version);
        } else {
            // In case we could not create the above string go for the static version instead
            ap_add_version_component(pconf, "GnuTLS/" GNUTLS_VERSION "-static");
        }
    }

    return OK;
}

void mgs_hook_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv = APR_SUCCESS;
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);

    /* if we use PKCS #11 reinitialize it */
    if (mgs_pkcs11_reinit(s) < 0) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                    "GnuTLS: Failed to reinitialize PKCS #11");
	    exit(-1);
    }

    if (sc->cache_enable == GNUTLS_ENABLED_TRUE)
    {
        rv = mgs_cache_child_init(p, s, sc->cache, MGS_CACHE_MUTEX_NAME);
        if (rv != APR_SUCCESS)
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                    "Child init for session cache failed!");
    }

    if (sc->ocsp_cache != NULL)
    {
        rv = mgs_cache_child_init(p, s, sc->ocsp_cache,
                                  MGS_OCSP_CACHE_MUTEX_NAME);
        if (rv != APR_SUCCESS)
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                    "Child init for OCSP cache failed!");
    }

    /* reinit OCSP request mutex */
    const char *lockfile = apr_global_mutex_lockfile(sc->ocsp_mutex);
    rv = apr_global_mutex_child_init(&sc->ocsp_mutex, lockfile, p);
    if (rv != APR_SUCCESS)
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Failed to reinit mutex '" MGS_OCSP_MUTEX_NAME "'.");

    /* Block SIGPIPE Signals */
    rv = apr_signal_block(SIGPIPE);
    if(rv != APR_SUCCESS) {
        /* error sending output */
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                "GnuTLS: Error Blocking SIGPIPE Signal!");
    }
}

const char *mgs_hook_http_scheme(const request_rec * r) {
    mgs_srvconf_rec *sc;

    if (r == NULL)
        return NULL;

    sc = (mgs_srvconf_rec *) ap_get_module_config(r->
            server->module_config,
            &gnutls_module);

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return NULL;
    }

    return "https";
}

apr_port_t mgs_hook_default_port(const request_rec * r) {
    mgs_srvconf_rec *sc;

    if (r == NULL)
        return 0;

    sc = (mgs_srvconf_rec *) ap_get_module_config(r->
            server->module_config,
            &gnutls_module);

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return 0;
    }

    return 443;
}



typedef struct {
    mgs_handle_t *ctxt;
    mgs_srvconf_rec *sc;
    const char *sni_name;
} vhost_cb_rec;

/**
 * Matches the current vhost's ServerAlias directives
 *
 * @param x vhost callback record
 * @param s server record
 * @param tsc mod_gnutls server data for `s`
 *
 * @return true if a match, false otherwise
 *
 */
int check_server_aliases(vhost_cb_rec *x, server_rec * s, mgs_srvconf_rec *tsc)
{
    apr_array_header_t *names;
    int rv = 0;
    char ** name;

    /* Check ServerName First! */
    if (strcasecmp(x->sni_name, s->server_hostname) == 0) {
        // We have a match, save this server configuration
        x->sc = tsc;
        rv = 1;
        /* Check any ServerAlias directives */
    } else if(s->names->nelts) {
        names = s->names;
        name = (char **) names->elts;
        for (int i = 0; i < names->nelts; ++i)
        {
            if (!name[i])
                continue;
            if (strcasecmp(x->sni_name, name[i]) == 0)
            {
                // We have a match, save this server configuration
                x->sc = tsc;
                rv = 1;
            }
        }
        /* ServerAlias directives may contain wildcards, check those last. */
    } else if(s->wild_names->nelts) {
        names = s->wild_names;
        name = (char **) names->elts;
        for (int i = 0; i < names->nelts; ++i)
        {
            if (!name[i])
                continue;
            if (ap_strcasecmp_match(x->sni_name, name[i]) == 0)
            {
                x->sc = tsc;
                rv = 1;
            }
        }
    }
    return rv;
}

static int vhost_cb(void *baton, conn_rec *conn, server_rec * s)
{
    mgs_srvconf_rec *tsc;
    vhost_cb_rec *x = baton;
    int ret;

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    tsc = (mgs_srvconf_rec *) ap_get_module_config(s->module_config,
            &gnutls_module);

    if (tsc->enabled != GNUTLS_ENABLED_TRUE) {
        return 0;
    }

    if (tsc->certs_x509_chain_num > 0) {
        /* this check is there to warn administrator of any missing hostname
         * in the certificate. */
        ret = gnutls_x509_crt_check_hostname(tsc->certs_x509_crt_chain[0], s->server_hostname);
        if (0 == ret)
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, conn,
                          "GnuTLS: the certificate doesn't match requested "
                          "hostname '%s'", s->server_hostname);
    } else {
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, conn,
                      "GnuTLS: SNI request for '%s' but no X.509 certs "
                      "available at all",
                      s->server_hostname);
    }
	return check_server_aliases(x, s, tsc);
}

/**
 * Get SNI data from GnuTLS (if any) and search for a matching virtual
 * host configuration. This method is called from the post client
 * hello function.
 *
 * @param ctxt the mod_gnutls connection handle
 *
 * @return either the matching mod_gnutls server config, or `NULL`
 */
mgs_srvconf_rec *mgs_find_sni_server(mgs_handle_t *ctxt)
{
    if (ctxt->sni_name == NULL)
    {
        const char *sni_name = mgs_server_name_get(ctxt);
        if (sni_name != NULL)
            ctxt->sni_name = sni_name;
        else
            return NULL;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, ctxt->c,
                  "%s: client requested server '%s'.",
                  __func__, ctxt->sni_name);

    /* Search for vhosts matching connection parameters and the
     * SNI. If a match is found, cbx.sc will contain the mod_gnutls
     * server config for the vhost. */
    vhost_cb_rec cbx = {
        .ctxt = ctxt,
        .sc = NULL,
        .sni_name = ctxt->sni_name
    };
    int rv = ap_vhost_iterate_given_conn(ctxt->c, vhost_cb, &cbx);
    if (rv == 1) {
        return cbx.sc;
    }
    return NULL;
}



#ifdef ENABLE_EARLY_SNI
/**
 * Pre client hello hook function for GnuTLS that implements early SNI
 * processing using `gnutls_ext_raw_parse()` (available since GnuTLS
 * 3.6.3). Reading the SNI (if any) before GnuTLS processes the client
 * hello allows loading virtual host settings that cannot be changed
 * in the post client hello hook, including ALPN proposals (required
 * for HTTP/2 support using the `Protocols` directive). In addition to
 * ALPN this function configures the server credentials.
 *
 * The function signature is required by the GnuTLS API.
 *
 * @param session the current session
 * @param htype handshake message type
 * @param when hook position relative to GnuTLS processing
 * @param incoming true if the message is incoming, for client hello
 * that means the hook is running on the server
 * @param msg raw message data
 *
 * @return `GNUTLS_E_SUCCESS` or a GnuTLS error code
 */
static int early_sni_hook(gnutls_session_t session,
                          unsigned int htype,
                          unsigned when,
                          unsigned int incoming,
                          const gnutls_datum_t *msg)
{
    if (!incoming)
        return 0;

    mgs_handle_t *ctxt = (mgs_handle_t *) gnutls_session_get_ptr(session);

    /* This is a hook for pre client hello ONLY! */
    if (htype != GNUTLS_HANDSHAKE_CLIENT_HELLO || when != GNUTLS_HOOK_PRE)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EINVAL, ctxt->c,
                      "%s called outside pre client hello hook, this "
                      "indicates a programming error!",
                      __func__);
        return GNUTLS_E_SELF_TEST_ERROR;
    }

    int ret = gnutls_ext_raw_parse(session, mgs_sni_ext_hook, msg,
                                   GNUTLS_EXT_RAW_FLAG_TLS_CLIENT_HELLO);
    if (ret == 0 && ctxt->sni_name != NULL)
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                      "%s found SNI name: '%s'",
                      __func__, ctxt->sni_name);

    /* try to find a virtual host for that name */
    mgs_srvconf_rec *tsc = mgs_find_sni_server(ctxt);
    if (tsc != NULL)
    {
        /* Found a TLS vhost based on the SNI, configure the
         * connection context. */
        ctxt->sc = tsc;
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                      "%s: Selected virtual host %s from early SNI, "
                      "connection server is still %s.",
                      __func__, ctxt->sc->s->server_hostname,
                      ctxt->c->base_server->server_hostname);
    }

    reload_session_credentials(ctxt);

    prepare_alpn_proposals(ctxt);

    return ret;
}
#endif



/**
 * This function is intended as a cleanup handler for connections
 * using GnuTLS. If attached to the connection pool, it ensures that
 * session resources are released with the connection pool even if the
 * session wasn't terminated properly.
 *
 * @param data must point to the mgs_handle_t associated with the
 * connection
 */
static apr_status_t cleanup_gnutls_session(void *data)
{
    /* nothing to do */
    if (data == NULL)
        return APR_SUCCESS;

    /* check if session needs closing */
    mgs_handle_t *ctxt = (mgs_handle_t *) data;
    if (ctxt->session != NULL)
    {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, APR_ECONNABORTED, ctxt->c,
                      "%s: connection pool cleanup in progress but %sTLS "
                      "session hasn't been terminated, trying to close",
                      __func__, IS_PROXY_STR(ctxt));
        int ret;
        /* Try A Clean Shutdown */
        do
            ret = gnutls_bye(ctxt->session, GNUTLS_SHUT_WR);
        while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
        if (ret != GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_INFO, APR_EGENERAL, ctxt->c,
                          "%s: error while closing TLS %sconnection: %s (%d)",
                          __func__, IS_PROXY_STR(ctxt),
                          gnutls_strerror(ret), ret);
        else
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                          "%s: TLS %sconnection closed.",
                          __func__, IS_PROXY_STR(ctxt));
        /* De-Initialize Session */
        gnutls_deinit(ctxt->session);
        ctxt->session = NULL;
    }
    return APR_SUCCESS;
}

static void create_gnutls_handle(conn_rec * c)
{
    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);

    /* Get connection specific configuration */
    mgs_handle_t *ctxt = init_gnutls_ctxt(c);
    ctxt->enabled = GNUTLS_ENABLED_TRUE;
    ctxt->status = 0;
    ctxt->input_rc = APR_SUCCESS;
    ctxt->input_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    ctxt->input_cbuf.length = 0;
    ctxt->output_rc = APR_SUCCESS;
    ctxt->output_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    ctxt->output_blen = 0;
    ctxt->output_length = 0;

    /* Initialize GnuTLS Library */
    int err = 0;
    if (ctxt->is_proxy == GNUTLS_ENABLED_TRUE)
    {
        /* this is an outgoing proxy connection, client mode */
        err = gnutls_init(&ctxt->session, GNUTLS_CLIENT);
        if (err != GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_ERR, err, c,
                          "gnutls_init for proxy connection failed: %s (%d)",
                          gnutls_strerror(err), err);
    }
    else
    {
        /* incoming connection, server mode */
        err = gnutls_init(&ctxt->session, GNUTLS_SERVER);
        if (err != GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_ERR, err, c,
                          "gnutls_init for server side failed: %s (%d)",
                          gnutls_strerror(err), err);
    }

    /* Ensure TLS session resources are released when the connection
     * pool is cleared, if the filters haven't done that already. */
    apr_pool_pre_cleanup_register(c->pool, ctxt, cleanup_gnutls_session);

    /* Set Default Priority */
	err = gnutls_priority_set(ctxt->session, mgs_get_default_prio());
    if (err != GNUTLS_E_SUCCESS)
        ap_log_cerror(APLOG_MARK, APLOG_ERR, err, c,
                      "gnutls_priority_set failed!");

#ifdef ENABLE_EARLY_SNI
    /* Pre-handshake hook, EXPERIMENTAL */
    gnutls_handshake_set_hook_function(ctxt->session,
                                       GNUTLS_HANDSHAKE_CLIENT_HELLO,
                                       GNUTLS_HOOK_PRE, early_sni_hook);
#else
    prepare_alpn_proposals(ctxt);
#endif

    /* Post client hello hook (called after GnuTLS has parsed it) */
    gnutls_handshake_set_post_client_hello_function(ctxt->session,
            post_client_hello_hook);

    /* Set GnuTLS user pointer, so we can access the module session
     * context in GnuTLS callbacks */
    gnutls_session_set_ptr(ctxt->session, ctxt);

    /* If mod_gnutls is the TLS server, early_sni_hook (or
     * post_client_hello_hook, if early SNI is not available) will
     * load appropriate credentials during the handshake. However,
     * when handling a proxy backend connection, mod_gnutls acts as
     * TLS client and credentials must be loaded here. */
    if (ctxt->is_proxy == GNUTLS_ENABLED_TRUE)
    {
        /* Set anonymous client credentials for proxy connections */
        gnutls_credentials_set(ctxt->session, GNUTLS_CRD_ANON,
                               ctxt->sc->anon_client_creds);
        /* Set x509 credentials */
        gnutls_credentials_set(ctxt->session, GNUTLS_CRD_CERTIFICATE,
                               ctxt->sc->proxy_x509_creds);
        /* Load priorities from the server configuration */
        err = gnutls_priority_set(ctxt->session, ctxt->sc->proxy_priorities);
        if (err != GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_ERR, err, c,
                          "%s: setting priorities for proxy connection "
                          "failed: %s (%d)",
                          __func__, gnutls_strerror(err), err);
    }

    /* Initialize Session Cache */
    mgs_cache_session_init(ctxt);

    /* Set pull, push & ptr functions */
    gnutls_transport_set_pull_function(ctxt->session,
            mgs_transport_read);
    gnutls_transport_set_push_function(ctxt->session,
            mgs_transport_write);
    gnutls_transport_set_ptr(ctxt->session, ctxt);
    /* Add IO filters */
    ctxt->input_filter = ap_add_input_filter(GNUTLS_INPUT_FILTER_NAME,
            ctxt, NULL, c);
    ctxt->output_filter = ap_add_output_filter(GNUTLS_OUTPUT_FILTER_NAME,
            ctxt, NULL, c);
}

int mgs_hook_pre_connection(conn_rec * c, void *csd __attribute__((unused)))
{
    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);

    if (c->master)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "%s declined secondary connection", __func__);
        return DECLINED;
    }

    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(c->base_server->module_config, &gnutls_module);
    mgs_handle_t *ctxt = (mgs_handle_t *)
        ap_get_module_config(c->conn_config, &gnutls_module);

    if ((sc && (!sc->enabled))
        || (ctxt && ctxt->enabled == GNUTLS_ENABLED_FALSE))
    {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "%s declined connection",
                      __func__);
        return DECLINED;
    }

    create_gnutls_handle(c);
    return OK;
}



/**
 * process_connection hook: Do a zero byte read to trigger the
 * handshake. Doesn't change anything for traditional protocols that
 * just do reads, but HTTP/2 needs the TLS handshake and ALPN to
 * happen before its process_connection hook runs.
 */
int mgs_hook_process_connection(conn_rec* c)
{
    mgs_handle_t *ctxt = (mgs_handle_t *)
        ap_get_module_config(c->conn_config, &gnutls_module);

    if ((ctxt != NULL) && (ctxt->enabled == GNUTLS_ENABLED_TRUE))
    {
        /* This connection is supposed to use TLS. Give the filters a
         * kick with a zero byte read to trigger the handshake. */
        apr_bucket_brigade* temp =
            apr_brigade_create(c->pool, c->bucket_alloc);
        ap_get_brigade(c->input_filters, temp,
                       AP_MODE_INIT, APR_BLOCK_READ, 0);
        apr_brigade_destroy(temp);
    }
    return DECLINED;
}



/* Post request hook, checks if TLS connection and vhost match */
int mgs_req_vhost_check(request_rec *r)
{
    /* mod_gnutls server record for the request vhost */
    mgs_srvconf_rec *r_sc = (mgs_srvconf_rec *)
        ap_get_module_config(r->server->module_config, &gnutls_module);
    mgs_handle_t *ctxt = get_effective_gnutls_ctxt(r->connection);

    /* Nothing to check for non-TLS and outgoing proxy connections */
    if (ctxt == NULL || !ctxt->enabled || ctxt->is_proxy)
        return DECLINED;

    if (ctxt->sc != r_sc)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, ctxt->c,
                      "%s: Mismatch between handshake and request servers!",
                      __func__);
        return HTTP_MISDIRECTED_REQUEST;
    }

    if (!ctxt->sni_name)
        return DECLINED;

    /* Got an SNI name, so verify it matches. */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, ctxt->c,
                  "%s: Checking request hostname against SNI name '%s'.",
                  __func__, ctxt->sni_name);

    if (!r->hostname)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r->connection,
                      "Client requested '%s' via SNI, but provided "
                      "no hostname in HTTP request!", ctxt->sni_name);
        return HTTP_MISDIRECTED_REQUEST;
    }

    if (strcasecmp(r->hostname, ctxt->sni_name) != 0)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r->connection,
                      "Client requested '%s' via SNI, but '%s' in "
                      "the HTTP request!", ctxt->sni_name, r->hostname);
        return HTTP_MISDIRECTED_REQUEST;
    }

    return DECLINED;
}



int mgs_hook_fixups(request_rec * r) {
    unsigned char sbuf[GNUTLS_MAX_SESSION_ID];
    const char *tmp;
    size_t len;
    mgs_handle_t *ctxt;
    int rv = OK;

    if (r == NULL)
        return DECLINED;

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    apr_table_t *env = r->subprocess_env;

    ctxt = get_effective_gnutls_ctxt(r->connection);

    if (!ctxt || ctxt->enabled != GNUTLS_ENABLED_TRUE || ctxt->session == NULL)
    {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "request declined in %s", __func__);
        return DECLINED;
    }

    apr_table_setn(env, "HTTPS", "on");

    apr_table_setn(env, "SSL_VERSION_LIBRARY",
            "GnuTLS/" LIBGNUTLS_VERSION);
    apr_table_setn(env, "SSL_VERSION_INTERFACE",
            "mod_gnutls/" MOD_GNUTLS_VERSION);

    apr_table_setn(env, "SSL_PROTOCOL",
            gnutls_protocol_get_name(gnutls_protocol_get_version(ctxt->session)));

    /* should have been called SSL_CIPHERSUITE instead */
    apr_table_setn(env, "SSL_CIPHER",
            gnutls_cipher_suite_get_name(gnutls_kx_get(ctxt->session),
                                         gnutls_cipher_get(ctxt->session),
                                         gnutls_mac_get(ctxt->session)));

#if GNUTLS_VERSION_NUMBER >= 0x030600
    /* Compression support has been removed since GnuTLS 3.6.0 */
    apr_table_setn(env, "SSL_COMPRESS_METHOD", "NULL");
#else
    apr_table_setn(env, "SSL_COMPRESS_METHOD",
            gnutls_compression_get_name(gnutls_compression_get(ctxt->session)));
#endif

#ifdef ENABLE_SRP
    if (ctxt->sc->srp_tpasswd_conf_file != NULL && ctxt->sc->srp_tpasswd_file != NULL) {
        tmp = gnutls_srp_server_get_username(ctxt->session);
        apr_table_setn(env, "SSL_SRP_USER", (tmp != NULL) ? tmp : "");
    } else {
        apr_table_unset(env, "SSL_SRP_USER");
    }
#endif

    if (apr_table_get(env, "SSL_CLIENT_VERIFY") == NULL)
        apr_table_setn(env, "SSL_CLIENT_VERIFY", "NONE");

    unsigned int key_size = 8 * gnutls_cipher_get_key_size(gnutls_cipher_get(ctxt->session));
    tmp = apr_psprintf(r->pool, "%u", key_size);

    apr_table_setn(env, "SSL_CIPHER_USEKEYSIZE", tmp);

    apr_table_setn(env, "SSL_CIPHER_ALGKEYSIZE", tmp);

    apr_table_setn(env, "SSL_CIPHER_EXPORT",
            (key_size <= 40) ? "true" : "false");

    int dhsize = gnutls_dh_get_prime_bits(ctxt->session);
    if (dhsize > 0) {
        tmp = apr_psprintf(r->pool, "%d", dhsize);
        apr_table_setn(env, "SSL_DH_PRIME_BITS", tmp);
    }

    len = sizeof (sbuf);
    gnutls_session_get_id(ctxt->session, sbuf, &len);
    apr_table_setn(env, "SSL_SESSION_ID",
                   apr_pescape_hex(r->pool, sbuf, len, 0));

    if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_X509) {
        mgs_add_common_cert_vars(r, ctxt->sc->certs_x509_crt_chain[0], 0,
                                 ctxt->sc->export_certificates_size);
    }

    return rv;
}

int mgs_hook_authz(request_rec * r) {
    int rv;
    mgs_handle_t *ctxt;
    mgs_dirconf_rec *dc;

    if (r == NULL)
        return DECLINED;

    dc = ap_get_module_config(r->per_dir_config, &gnutls_module);

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    ctxt = get_effective_gnutls_ctxt(r->connection);

    if (!ctxt || ctxt->session == NULL) {
        return DECLINED;
    }

    if (dc->client_verify_mode == GNUTLS_CERT_IGNORE) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "GnuTLS: Directory set to Ignore Client Certificate!");
    } else {
        if (ctxt->sc->client_verify_mode < dc->client_verify_mode) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "GnuTLS: Attempting to rehandshake with peer. %d %d",
                    ctxt->sc->client_verify_mode,
                    dc->client_verify_mode);

            /* If we already have a client certificate, there's no point in
             * re-handshaking... */
            rv = mgs_cert_verify(r, ctxt);
            if (rv != DECLINED && rv != HTTP_FORBIDDEN)
                return rv;

            gnutls_certificate_server_set_request
                    (ctxt->session, dc->client_verify_mode);

            if (mgs_rehandshake(ctxt) != 0) {
                return HTTP_FORBIDDEN;
            }
        } else if (ctxt->sc->client_verify_mode ==
                GNUTLS_CERT_IGNORE) {
#if MOD_GNUTLS_DEBUG
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "GnuTLS: Peer is set to IGNORE");
#endif
            return DECLINED;
        }
        rv = mgs_cert_verify(r, ctxt);
        if (rv != DECLINED
            && (rv != HTTP_FORBIDDEN
                || dc->client_verify_mode == GNUTLS_CERT_REQUIRE
                || (dc->client_verify_mode == -1
                    && ctxt->sc->client_verify_mode == GNUTLS_CERT_REQUIRE)))
        {
            return rv;
        }
    }

    return DECLINED;
}

/* variables that are not sent by default:
 *
 * SSL_CLIENT_CERT 	string 	PEM-encoded client certificate
 * SSL_SERVER_CERT 	string 	PEM-encoded client certificate
 */

/* @param side is either 0 for SERVER or 1 for CLIENT
 *
 * @param export_cert_size (int) maximum size for environment variable
 * to use for the PEM-encoded certificate (0 means do not export)
 */
#define MGS_SIDE(suffix) ((side==0) ? "SSL_SERVER" suffix : "SSL_CLIENT" suffix)

static void mgs_add_common_cert_vars(request_rec * r, gnutls_x509_crt_t cert, int side, size_t export_cert_size) {
    unsigned char sbuf[64]; /* buffer to hold serials */
    char buf[AP_IOBUFSIZE];
    const char *tmp;
    char *tmp2;
    size_t len;
    int ret;

    if (r == NULL)
        return;

    apr_table_t *env = r->subprocess_env;

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    if (export_cert_size > 0) {
        len = 0;
        ret = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, NULL, &len);
        if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
            if (len >= export_cert_size) {
                apr_table_setn(env, MGS_SIDE("_CERT"), "GNUTLS_CERTIFICATE_SIZE_LIMIT_EXCEEDED");
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "GnuTLS: Failed to export too-large X.509 certificate to environment");
            } else {
                char* cert_buf = apr_palloc(r->pool, len + 1);
                if (cert_buf != NULL && gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, cert_buf, &len) >= 0) {
                    cert_buf[len] = 0;
                    apr_table_setn(env, MGS_SIDE("_CERT"), cert_buf);
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                                  "GnuTLS: failed to export X.509 certificate");
                }
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "GnuTLS: dazed and confused about X.509 certificate size");
        }
    }

    len = sizeof (buf);
    gnutls_x509_crt_get_dn(cert, buf, &len);
    apr_table_setn(env, MGS_SIDE("_S_DN"), apr_pstrmemdup(r->pool, buf, len));

    len = sizeof (buf);
    gnutls_x509_crt_get_issuer_dn(cert, buf, &len);
    apr_table_setn(env, MGS_SIDE("_I_DN"), apr_pstrmemdup(r->pool, buf, len));

    len = sizeof (sbuf);
    gnutls_x509_crt_get_serial(cert, sbuf, &len);
    apr_table_setn(env, MGS_SIDE("_M_SERIAL"),
                   apr_pescape_hex(r->pool, sbuf, len, 0));

    ret = gnutls_x509_crt_get_version(cert);
    if (ret > 0)
        apr_table_setn(env, MGS_SIDE("_M_VERSION"),
                       apr_psprintf(r->pool, "%u", ret));

    apr_table_setn(env, MGS_SIDE("_CERT_TYPE"), "X.509");

    tmp =
            mgs_time2sz(gnutls_x509_crt_get_expiration_time
            (cert), buf, sizeof (buf));
    apr_table_setn(env, MGS_SIDE("_V_END"), apr_pstrdup(r->pool, tmp));

    tmp =
            mgs_time2sz(gnutls_x509_crt_get_activation_time
            (cert), buf, sizeof (buf));
    apr_table_setn(env, MGS_SIDE("_V_START"), apr_pstrdup(r->pool, tmp));

    ret = gnutls_x509_crt_get_signature_algorithm(cert);
    if (ret >= 0) {
        apr_table_setn(env, MGS_SIDE("_A_SIG"),
                gnutls_sign_algorithm_get_name(ret));
    }

    ret = gnutls_x509_crt_get_pk_algorithm(cert, NULL);
    if (ret >= 0) {
        apr_table_setn(env, MGS_SIDE("_A_KEY"),
                gnutls_pk_algorithm_get_name(ret));
    }

    /* export all the alternative names (DNS, RFC822 and URI) */
    for (int i = 0; !(ret < 0); i++)
    {
        const char *san, *sanlabel;
        len = 0;
        ret = gnutls_x509_crt_get_subject_alt_name(cert, i,
                NULL, &len,
                NULL);

        if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER && len > 1) {
            tmp2 = apr_palloc(r->pool, len + 1);

            ret =
                    gnutls_x509_crt_get_subject_alt_name(cert, i,
                    tmp2,
                    &len,
                    NULL);
            tmp2[len] = 0;

            sanlabel = apr_psprintf(r->pool, "%s%u", MGS_SIDE("_S_AN"), i);
            if (ret == GNUTLS_SAN_DNSNAME) {
                san = apr_psprintf(r->pool, "DNSNAME:%s", tmp2);
            } else if (ret == GNUTLS_SAN_RFC822NAME) {
                san = apr_psprintf(r->pool, "RFC822NAME:%s", tmp2);
            } else if (ret == GNUTLS_SAN_URI) {
                san = apr_psprintf(r->pool, "URI:%s", tmp2);
            } else {
                san = "UNSUPPORTED";
            }
            apr_table_setn(env, sanlabel, san);
        }
    }
}



/* TODO: Allow client sending a X.509 certificate chain */
static int mgs_cert_verify(request_rec * r, mgs_handle_t * ctxt) {
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size;
    /* assume the certificate is invalid unless explicitly set
     * otherwise */
    unsigned int status = GNUTLS_CERT_INVALID;
    int rv = GNUTLS_E_NO_CERTIFICATE_FOUND, ret;
    unsigned int ch_size = 0;

    // TODO: union no longer needed here after removing its "pgp" component.
    union {
        gnutls_x509_crt_t x509[MAX_CHAIN_SIZE];
    } cert;
    apr_time_t expiration_time, cur_time;

    if (r == NULL || ctxt == NULL || ctxt->session == NULL)
        return HTTP_FORBIDDEN;

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    cert_list =
            gnutls_certificate_get_peers(ctxt->session, &cert_list_size);

    if (cert_list == NULL || cert_list_size == 0) {
        /* It is perfectly OK for a client not to send a certificate if on REQUEST mode
         */
        if (ctxt->sc->client_verify_mode == GNUTLS_CERT_REQUEST)
            return OK;

        /* no certificate provided by the client, but one was required. */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Failed to Verify Peer: "
                "Client did not submit a certificate");
        return HTTP_FORBIDDEN;
    }

    if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_X509) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "GnuTLS: A Chain of %d certificate(s) was provided for validation",
                cert_list_size);

        for (ch_size = 0; ch_size < cert_list_size; ch_size++) {
            gnutls_x509_crt_init(&cert.x509[ch_size]);
            rv = gnutls_x509_crt_import(cert.x509[ch_size],
                    &cert_list[ch_size],
                    GNUTLS_X509_FMT_DER);
            // When failure to import, leave the loop
            if (rv != GNUTLS_E_SUCCESS) {
                if (ch_size < 1) {
                    ap_log_rerror(APLOG_MARK,
                            APLOG_INFO, 0, r,
                            "GnuTLS: Failed to Verify Peer: "
                            "Failed to import peer certificates.");
                    ret = HTTP_FORBIDDEN;
                    goto exit;
                }
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                        "GnuTLS: Failed to import some peer certificates. Using %d certificates",
                        ch_size);
                rv = GNUTLS_E_SUCCESS;
                break;
            }
        }
    } else
        return HTTP_FORBIDDEN;

    if (rv < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Failed to Verify Peer: "
                "Failed to import peer certificates.");
        ret = HTTP_FORBIDDEN;
        goto exit;
    }

    if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_X509) {
        apr_time_ansi_put(&expiration_time,
                gnutls_x509_crt_get_expiration_time
                (cert.x509[0]));

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "GnuTLS: Verifying list of %d certificate(s) via method '%s'",
                      ch_size, mgs_readable_cvm(ctxt->sc->client_verify_method));
        switch(ctxt->sc->client_verify_method) {
        case mgs_cvm_cartel:
            rv = gnutls_x509_crt_list_verify(cert.x509, ch_size,
                                             ctxt->sc->ca_list,
                                             ctxt->sc->ca_list_size,
                                             NULL, 0, 0, &status);
            break;
#ifdef ENABLE_MSVA
        case mgs_cvm_msva:
        {
            struct msv_response* resp = NULL;
            struct msv_query q = { .context="https", .peertype="client", .pkctype="x509pem" };
            msv_ctxt_t ctx = msv_ctxt_init(NULL);
            char cert_pem_buf[10 * 1024];
            size_t len = sizeof (cert_pem_buf);

            rv = 0;
            if (gnutls_x509_crt_export(cert.x509[0], GNUTLS_X509_FMT_PEM, cert_pem_buf, &len) >= 0) {
                /* FIXME : put together a name from the cert we received, instead of hard-coding this value: */
                q.peername = mgs_x509_construct_uid(r, cert.x509[0]);
                q.pkcdata = cert_pem_buf;
                rv = msv_query_agent(ctx, q, &resp);
                if (rv == LIBMSV_ERROR_SUCCESS) {
                    status = 0;
                } else if (rv == LIBMSV_ERROR_INVALID) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "GnuTLS: Monkeysphere validation failed: (message: %s)", resp->message);
                    status = GNUTLS_CERT_INVALID;
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "GnuTLS: Error communicating with the Monkeysphere Validation Agent: (%d) %s", rv, msv_strerror(ctx, rv));
                    status = GNUTLS_CERT_INVALID;
                    rv = -1;
                }
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "GnuTLS: Could not convert the client certificate to PEM format");
                status = GNUTLS_CERT_INVALID;
                rv = GNUTLS_E_ASN1_ELEMENT_NOT_FOUND;
            }
            msv_response_destroy(resp);
            msv_ctxt_destroy(ctx);
        }
            break;
#endif
        default:
            /* If this block is reached, that indicates a
             * configuration error or bug in mod_gnutls (invalid value
             * of ctxt->sc->client_verify_method). */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "GnuTLS: Failed to Verify X.509 Peer: method '%s' is not supported",
                          mgs_readable_cvm(ctxt->sc->client_verify_method));
            rv = GNUTLS_E_UNIMPLEMENTED_FEATURE;
        }

    } else {
        /* Unknown certificate type */
        rv = GNUTLS_E_UNIMPLEMENTED_FEATURE;
    }

    /* "goto exit" at the end of this block skips evaluation of the
     * "status" variable */
    if (rv < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Failed to Verify Peer certificate: (%d) %s",
                rv, gnutls_strerror(rv));
        if (rv == GNUTLS_E_NO_CERTIFICATE_FOUND)
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r,
                "GnuTLS: No certificate was found for verification. Did you set the GnuTLSClientCAFile directive?");
        ret = HTTP_FORBIDDEN;
        goto exit;
    }

    /* TODO: X509 CRL Verification. */
    /* May add later if anyone needs it.
     */
    /* ret = gnutls_x509_crt_check_revocation(crt, crl_list, crl_list_size); */

    cur_time = apr_time_now();

    if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Could not find Signer for Peer Certificate");
    }

    if (status & GNUTLS_CERT_SIGNER_NOT_CA) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Peer's Certificate signer is not a CA");
    }

    if (status & GNUTLS_CERT_INSECURE_ALGORITHM) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Peer's Certificate is using insecure algorithms");
    }

    if (status & GNUTLS_CERT_EXPIRED
            || status & GNUTLS_CERT_NOT_ACTIVATED) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Peer's Certificate signer is expired or not yet activated");
    }

    if (status & GNUTLS_CERT_INVALID) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Peer Certificate is invalid.");
    } else if (status & GNUTLS_CERT_REVOKED) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Peer Certificate is revoked.");
    }

    mgs_add_common_cert_vars(r, cert.x509[0], 1, ctxt->sc->export_certificates_size);

    {
        /* days remaining */
        unsigned long remain =
                (apr_time_sec(expiration_time) -
                apr_time_sec(cur_time)) / 86400;
        apr_table_setn(r->subprocess_env, "SSL_CLIENT_V_REMAIN",
                apr_psprintf(r->pool, "%lu", remain));
    }

    if (status == 0) {
        apr_table_setn(r->subprocess_env, "SSL_CLIENT_VERIFY",
                "SUCCESS");
        ret = OK;
    } else {
        apr_table_setn(r->subprocess_env, "SSL_CLIENT_VERIFY",
                "FAILED");
        if (ctxt->sc->client_verify_mode == GNUTLS_CERT_REQUEST)
            ret = OK;
        else
            ret = HTTP_FORBIDDEN;
    }

exit:
    if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_X509)
        for (unsigned int i = 0; i < ch_size; i++)
            gnutls_x509_crt_deinit(cert.x509[i]);

    return ret;
}



#ifdef ENABLE_MSVA
/* this section of code is used only when trying to talk to the MSVA */
static const char* mgs_x509_leaf_oid_from_dn(apr_pool_t *pool, const char* oid, gnutls_x509_crt_t cert) {
    int rv=GNUTLS_E_SUCCESS, i;
    size_t sz=0, lastsz=0;
    char* data=NULL;

    i = -1;
    while(rv != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        i++;
        lastsz=sz;
        sz=0;
        rv = gnutls_x509_crt_get_dn_by_oid (cert, oid, i, 0, NULL, &sz);
    }
    if (i > 0) {
        data = apr_palloc(pool, lastsz);
        sz=lastsz;
        rv = gnutls_x509_crt_get_dn_by_oid (cert, oid, i-1, 0, data, &sz);
        if (rv == GNUTLS_E_SUCCESS)
            return data;
    }
    return NULL;
}

static const char* mgs_x509_first_type_from_san(apr_pool_t *pool, gnutls_x509_subject_alt_name_t target, gnutls_x509_crt_t cert) {
    int rv=GNUTLS_E_SUCCESS;
    size_t sz;
    char* data=NULL;
    unsigned int i;
    gnutls_x509_subject_alt_name_t thistype;

    i = 0;
    while(rv != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        sz = 0;
        rv = gnutls_x509_crt_get_subject_alt_name2(cert, i, NULL, &sz, &thistype, NULL);
        if (rv == GNUTLS_E_SHORT_MEMORY_BUFFER && thistype == target) {
            data = apr_palloc(pool, sz);
            rv = gnutls_x509_crt_get_subject_alt_name2(cert, i, data, &sz, &thistype, NULL);
            if (rv >=0 && (thistype == target))
                return data;
        }
        i++;
    }
    return NULL;
}


/* Create a string representing a candidate User ID from an X.509
 * certificate

 * We need this for client certification because a client gives us a
 * certificate, but doesn't tell us (in any other way) who they are
 * trying to authenticate as.

 * one complaint might be "but the user wanted to be another identity,
 * which is also in the certificate (e.g. in a SubjectAltName)"
 * However, given that any user can regenerate their own X.509
 * certificate with their own public key content, they should just do
 * so, and not expect us to guess at their identity :)

 * This function allocates it's response from the pool given it.  When
 * that pool is reclaimed, the response will also be deallocated.

 * FIXME: what about extracting a server-style cert
 *        (e.g. https://imposter.example) from the DN or any sAN?

 * FIXME: what if we want to call this outside the context of a
 *        request?  That complicates the logging.
 */
static const char* mgs_x509_construct_uid(request_rec *r, gnutls_x509_crt_t cert) {
    /* basic strategy, assuming humans are the users: we are going to
     * try to reconstruct a "conventional" User ID by pulling in a
     * name, comment, and e-mail address.
     */
    apr_pool_t *pool = r->pool;
    const char *name=NULL, *comment=NULL, *email=NULL;
    const char *ret=NULL;
    /* subpool for temporary allocation: */
    apr_pool_t *sp=NULL;

    if (APR_SUCCESS != apr_pool_create(&sp, pool))
        return NULL; /* i'm assuming that libapr would log this kind
                      * of error on its own */

     /* Name

     the name comes from the leaf commonName of the cert's Subject.

     (MAYBE: should we look at trying to assemble a candidate from
             givenName, surName, suffix, etc?  the "name" field
             appears to be case-insensitive, which seems problematic
             from what we expect; see:
             http://www.itu.int/rec/T-REC-X.520-200102-s/e )

     (MAYBE: should we try pulling a commonName or otherName or
             something from subjectAltName? see:
             https://tools.ietf.org/html/rfc5280#section-4.2.1.6
             GnuTLS does not support looking for Common Names in the
             SAN yet)
     */
    name = mgs_x509_leaf_oid_from_dn(sp, GNUTLS_OID_X520_COMMON_NAME, cert);

    /* Comment

       I am inclined to punt on this for now, as Comment has been so
       atrociously misused in OpenPGP.  Perhaps if there is a
       pseudonym (OID 2.5.4.65, aka GNUTLS_OID_X520_PSEUDONYM) field
       in the subject or sAN?
    */
    comment = mgs_x509_leaf_oid_from_dn(sp, GNUTLS_OID_X520_PSEUDONYM, cert);

    /* E-mail

       This should be the the first rfc822Name from the sAN.

       failing that, we'll take the leaf email in the certificate's
       subject; this is a deprecated use though.
     */
    email = mgs_x509_first_type_from_san(sp, GNUTLS_SAN_RFC822NAME, cert);
    if (email == NULL)
        email = mgs_x509_leaf_oid_from_dn(sp, GNUTLS_OID_PKCS9_EMAIL, cert);

    /* assemble all the parts: */

    /* must have at least a name or an e-mail. */
    if (name == NULL && email == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Need either a name or an e-mail address to get a User ID from an X.509 certificate.");
        goto end;
    }
    if (name) {
        if (comment) {
            if (email) {
                ret = apr_psprintf(pool, "%s (%s) <%s>", name, comment, email);
            } else {
                ret = apr_psprintf(pool, "%s (%s)", name, comment);
            }
        } else {
            if (email) {
                ret = apr_psprintf(pool, "%s <%s>", name, email);
            } else {
                ret = apr_pstrdup(pool, name);
            }
        }
    } else {
        if (comment) {
            ret = apr_psprintf(pool, "(%s) <%s>", comment, email);
        } else {
            ret = apr_psprintf(pool, "<%s>", email);
        }
    }

end:
    apr_pool_destroy(sp);
    return ret;
}
#endif /* ENABLE_MSVA */



/*
 * This hook writes the mod_gnutls status message for a mod_status
 * report. According to the comments in mod_status.h, the "flags"
 * parameter is a bitwise OR of the AP_STATUS_ flags.
 *
 * Note that this implementation gives flags explicitly requesting a
 * simple response priority, e.g. if AP_STATUS_SHORT is set, flags
 * requesting an HTML report will be ignored. As of Apache 2.4.10, the
 * following flags were defined in mod_status.h:
 *
 * AP_STATUS_SHORT (short, non-HTML report requested)
 * AP_STATUS_NOTABLE (HTML report without tables)
 * AP_STATUS_EXTENDED (detailed report)
 */
static int mgs_status_hook(request_rec *r, int flags)
{
    if (r == NULL)
        return OK;

    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(r->server->module_config, &gnutls_module);

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);

    if (flags & AP_STATUS_SHORT)
    {
        ap_rprintf(r, "Using GnuTLS version: %s\n", gnutls_check_version(NULL));
        ap_rputs("Built against GnuTLS version: " GNUTLS_VERSION "\n", r);
    }
    else
    {
        ap_rputs("<hr>\n", r);
        ap_rputs("<h2>GnuTLS Information:</h2>\n<dl>\n", r);

        ap_rprintf(r, "<dt>Using GnuTLS version:</dt><dd>%s</dd>\n",
                   gnutls_check_version(NULL));
        ap_rputs("<dt>Built against GnuTLS version:</dt><dd>"
                 GNUTLS_VERSION "</dd>\n", r);
        ap_rprintf(r, "<dt>Using TLS:</dt><dd>%s</dd>\n",
                   (sc->enabled == GNUTLS_ENABLED_FALSE ? "no" : "yes"));
    }

    if (sc->enabled != GNUTLS_ENABLED_FALSE)
    {
        mgs_handle_t* ctxt = get_effective_gnutls_ctxt(r->connection);
        if (ctxt && ctxt->session != NULL)
        {
            char* s_info = gnutls_session_get_desc(ctxt->session);
            if (s_info)
            {
                if (flags & AP_STATUS_SHORT)
                    ap_rprintf(r, "Current TLS session: %s\n", s_info);
                else
                    ap_rprintf(r, "<dt>Current TLS session:</dt><dd>%s</dd>\n",
                               s_info);
                gnutls_free(s_info);
            }
        }
    }

    if (!(flags & AP_STATUS_SHORT))
        ap_rputs("</dl>\n", r);

    if (sc->ocsp_cache)
        mgs_cache_status(sc->ocsp_cache, "GnuTLS OCSP Cache", r, flags);
    if (sc->cache_enable)
        mgs_cache_status(sc->cache, "GnuTLS Session Cache", r, flags);

    return OK;
}



/*
 * Callback to check the server certificate for proxy HTTPS
 * connections, to be used with
 * gnutls_certificate_set_verify_function.

 * Returns: 0 if certificate check was successful (certificate
 * trusted), non-zero otherwise (error during check or untrusted
 * certificate).
 */
static int gtls_check_server_cert(gnutls_session_t session)
{
    mgs_handle_t *ctxt = (mgs_handle_t *) gnutls_session_get_ptr(session);
    unsigned int status;

    /* Get peer hostname from a note left by mod_proxy */
    const char *peer_hostname =
        apr_table_get(ctxt->c->notes, PROXY_SNI_NOTE);
    if (peer_hostname == NULL)
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, ctxt->c,
                      "%s: " PROXY_SNI_NOTE " NULL, cannot check "
                      "peer's hostname", __func__);

    /* Verify certificate, including hostname match. Should
     * peer_hostname be NULL for some reason, the name is not
     * checked. */
    int err = gnutls_certificate_verify_peers3(session, peer_hostname,
                                               &status);
    if (err != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, ctxt->c,
                      "%s: server certificate check failed: %s (%d)",
                      __func__, gnutls_strerror(err), err);
        return err;
    }

    if (status == 0)
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctxt->c,
                      "%s: server certificate is trusted.",
                      __func__);
    else
    {
        gnutls_datum_t out;
        /* GNUTLS_CRT_X509: ATM, only X509 is supported for proxy
         * certs 0: according to function API, the last argument
         * should be 0 */
        err = gnutls_certificate_verification_status_print(status,
                                                           GNUTLS_CRT_X509,
                                                           &out, 0);
        if (err != GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, ctxt->c,
                          "%s: server verify print failed: %s (%d)",
                          __func__, gnutls_strerror(err), err);
        else
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, ctxt->c,
                          "%s: %s",
                          __func__, out.data);
        gnutls_free(out.data);
    }

    return status;
}



static apr_status_t cleanup_proxy_x509_credentials(void *arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) arg;

    if (sc->proxy_x509_creds)
    {
        /* This implicitly releases the associated trust list
         * sc->proxy_x509_tl, too. */
        gnutls_certificate_free_credentials(sc->proxy_x509_creds);
        sc->proxy_x509_creds = NULL;
        sc->proxy_x509_tl = NULL;
    }

    if (sc->anon_client_creds)
    {
        gnutls_anon_free_client_credentials(sc->anon_client_creds);
        sc->anon_client_creds = NULL;
    }

    /* Deinit proxy priorities only if set from
     * sc->proxy_priorities_str. Otherwise the server is using the
     * default global priority cache, which must not be deinitialized
     * here. */
    if (sc->proxy_priorities_str && sc->proxy_priorities)
    {
        gnutls_priority_deinit(sc->proxy_priorities);
        sc->proxy_priorities = NULL;
    }

    return APR_SUCCESS;
}



static apr_status_t load_proxy_x509_credentials(apr_pool_t *pconf,
                                                apr_pool_t *ptemp,
                                                server_rec *s)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    if (sc == NULL)
        return APR_EGENERAL;

    apr_status_t ret = APR_EINIT;
    int err = GNUTLS_E_SUCCESS;

    /* Cleanup function for the GnuTLS structures allocated below */
    apr_pool_cleanup_register(pconf, sc, cleanup_proxy_x509_credentials,
                              apr_pool_cleanup_null);

    /* Function pool, gets destroyed before exit. */
    apr_pool_t *pool;
    ret = apr_pool_create(&pool, ptemp);
    if (ret != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, ret, s,
                     "%s: failed to allocate function memory pool.", __func__);
        return ret;
    }

    /* allocate credentials structures */
    err = gnutls_certificate_allocate_credentials(&sc->proxy_x509_creds);
    if (err != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "%s: Failed to initialize proxy credentials: (%d) %s",
                     __func__, err, gnutls_strerror(err));
        return APR_EGENERAL;
    }
    err = gnutls_anon_allocate_client_credentials(&sc->anon_client_creds);
    if (err != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "%s: Failed to initialize anon credentials for proxy: "
                     "(%d) %s", __func__, err, gnutls_strerror(err));
        return APR_EGENERAL;
    }

    /* Check if the proxy priorities have been set, fail immediately
     * if not */
    if (sc->proxy_priorities_str == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "No GnuTLSProxyPriorities directive for host '%s:%d', "
                     "using default '%s'.",
                     s->server_hostname, s->addrs->host_port,
                     MGS_DEFAULT_PRIORITY);
        sc->proxy_priorities = mgs_get_default_prio();
    }
    else
    {
        /* parse proxy priorities */
        const char *err_pos = NULL;
        err = gnutls_priority_init(&sc->proxy_priorities,
                                   sc->proxy_priorities_str, &err_pos);
        if (err != GNUTLS_E_SUCCESS)
        {
            if (ret == GNUTLS_E_INVALID_REQUEST)
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "%s: Syntax error parsing proxy priorities "
                             "string at: %s",
                             __func__, err_pos);
            else
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "Error setting proxy priorities: %s (%d)",
                             gnutls_strerror(err), err);
            ret = APR_EGENERAL;
        }
    }

    /* load certificate and key for client auth, if configured */
    if (sc->proxy_x509_key_file && sc->proxy_x509_cert_file)
    {
        char* cert_file = ap_server_root_relative(pool,
                                                  sc->proxy_x509_cert_file);
        char* key_file = ap_server_root_relative(pool,
                                                 sc->proxy_x509_key_file);
        err = gnutls_certificate_set_x509_key_file(sc->proxy_x509_creds,
                                                   cert_file,
                                                   key_file,
                                                   GNUTLS_X509_FMT_PEM);
        if (err != GNUTLS_E_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "%s: loading proxy client credentials failed: %s (%d)",
                         __func__, gnutls_strerror(err), err);
            ret = APR_EGENERAL;
        }
    }
    else if (!sc->proxy_x509_key_file && sc->proxy_x509_cert_file)
    {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "%s: proxy key file not set!", __func__);
        ret = APR_EGENERAL;
    }
    else if (!sc->proxy_x509_cert_file && sc->proxy_x509_key_file)
    {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "%s: proxy certificate file not set!", __func__);
        ret = APR_EGENERAL;
    }
    else
        /* if both key and cert are NULL, client auth is not used */
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "%s: no client credentials for proxy", __func__);

    /* must be set if the server certificate is to be checked */
    if (sc->proxy_x509_ca_file)
    {
        /* initialize the trust list */
        err = gnutls_x509_trust_list_init(&sc->proxy_x509_tl, 0);
        if (err != GNUTLS_E_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "%s: gnutls_x509_trust_list_init failed: %s (%d)",
                         __func__, gnutls_strerror(err), err);
            ret = APR_EGENERAL;
        }

        char* ca_file = ap_server_root_relative(pool,
                                                sc->proxy_x509_ca_file);
        /* if no CRL is used, sc->proxy_x509_crl_file is NULL */
        char* crl_file = NULL;
        if (sc->proxy_x509_crl_file)
            crl_file = ap_server_root_relative(pool,
                                               sc->proxy_x509_crl_file);

        /* returns number of loaded elements */
        err = gnutls_x509_trust_list_add_trust_file(sc->proxy_x509_tl,
                                                    ca_file,
                                                    crl_file,
                                                    GNUTLS_X509_FMT_PEM,
                                                    0 /* tl_flags */,
                                                    0 /* tl_vflags */);
        if (err > 0)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s: proxy CA trust list: %d structures loaded",
                         __func__, err);
        else if (err == 0)
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "%s: proxy CA trust list is empty (%d)",
                         __func__, err);
        else /* err < 0 */
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "%s: error loading proxy CA trust list: %s (%d)",
                         __func__, gnutls_strerror(err), err);
            ret = APR_EGENERAL;
        }

        /* attach trust list to credentials */
        gnutls_certificate_set_trust_list(sc->proxy_x509_creds,
                                          sc->proxy_x509_tl, 0);
    }
    else
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "%s: no CA trust list for proxy connections, "
                     "TLS connections will fail!", __func__);

    gnutls_certificate_set_verify_function(sc->proxy_x509_creds,
                                           gtls_check_server_cert);
    apr_pool_destroy(pool);
    return ret;
}

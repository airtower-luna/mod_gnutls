/*
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
#include "gnutls_proxy.h"
#include "gnutls_util.h"

#include <gnutls/gnutls.h>

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



apr_status_t load_proxy_x509_credentials(apr_pool_t *pconf,
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

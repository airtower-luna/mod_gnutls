/**
 *  Copyright 2016 Thomas Klute
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

#include "gnutls_ocsp.h"
#include "mod_gnutls.h"

#include <apr_lib.h>
#include <apr_time.h>
#include <gnutls/ocsp.h>
#include <time.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif



#define _log_one_ocsp_fail(s, c)                                      \
    ap_log_cerror(APLOG_MARK, APLOG_INFO, APR_EGENERAL, (c),           \
                  "Reason for failed OCSP response verification: %s", (s))
/*
 * Log all matching reasons for verification failure
 */
static void _log_verify_fail_reason(const unsigned int verify, conn_rec *c)
{
    if (verify & GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND)
        _log_one_ocsp_fail("Signer cert not found", c);

    if (verify & GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR)
        _log_one_ocsp_fail("Signer cert keyusage error", c);

    if (verify & GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER)
        _log_one_ocsp_fail("Signer cert is not trusted", c);

    if (verify & GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM)
        _log_one_ocsp_fail("Insecure algorithm", c);

    if (verify & GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE)
        _log_one_ocsp_fail("Signature failure", c);

    if (verify & GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED)
        _log_one_ocsp_fail("Signer cert not yet activated", c);

    if (verify & GNUTLS_OCSP_VERIFY_CERT_EXPIRED)
        _log_one_ocsp_fail("Signer cert expired", c);
}



const char *mgs_store_ocsp_response_path(cmd_parms *parms,
                                         void *dummy __attribute__((unused)),
                                         const char *arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    sc->ocsp_response_file = ap_server_root_relative(parms->pool, arg);
    return NULL;
}



/**
 * Check if the provided OCSP response is usable for stapling in this
 * connection context. Returns GNUTLS_E_SUCCESS if yes.
 */
int check_ocsp_response(mgs_handle_t *ctxt, const gnutls_datum_t *ocsp_response)
{
    if (ctxt->sc->ocsp_trust == NULL)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "No OCSP trust list available for server \"%s\"!",
                      ctxt->c->base_server->server_hostname);
        return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

    gnutls_ocsp_resp_t resp;
    int ret = gnutls_ocsp_resp_init(&resp);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "Could not initialize OCSP response structure: %s (%d)",
                      gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }
    ret = gnutls_ocsp_resp_import(resp, ocsp_response);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "Importing OCSP response failed: %s (%d)",
                      gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }

    ret = gnutls_ocsp_resp_check_crt(resp, 0,
                                     ctxt->sc->certs_x509_crt_chain[0]);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "OCSP response is not for server certificate: %s (%d)",
                      gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }

    unsigned int verify;
    ret = gnutls_ocsp_resp_verify(resp, *(ctxt->sc->ocsp_trust), &verify, 0);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "OCSP response verification failed: %s (%d)",
                      gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }
    else
    {
        /* verification worked, check the result */
        if (verify != 0)
        {
            _log_verify_fail_reason(verify, ctxt->c);
            ret = GNUTLS_E_OCSP_RESPONSE_ERROR;
            goto resp_cleanup;
        }
        else
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                          "OCSP response is valid.");
    }

    /* OK, response is for our certificate and valid, let's get the
     * actual response data. */
    unsigned int cert_status;
    time_t this_update;
    time_t next_update;
    ret = gnutls_ocsp_resp_get_single(resp, 0, NULL, NULL, NULL, NULL,
                                      &cert_status, &this_update,
                                      &next_update, NULL, NULL);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "Could not get OCSP response data: %s (%d)",
                      gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }

    apr_time_t now = apr_time_now();
    apr_time_t valid_at;
    apr_time_ansi_put(&valid_at, this_update);
    /* Buffer for human-readable times produced by apr_rfc822_date,
     * see apr_time.h */
    char date_str[APR_RFC822_DATE_LEN];
    apr_rfc822_date(date_str, valid_at);

    if (now < valid_at)
    {
        /* We don't know if our clock or that of the OCSP responder is
         * out of sync, so warn but continue. */
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, APR_EGENERAL, ctxt->c,
                      "OSCP response claims to be from future (%s), check "
                      "time synchronization!", date_str);
    }

    if (next_update == (time_t) -1)
        ap_log_cerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, ctxt->c,
                      "OSCP response does not contain nextUpdate info.");
    else
    {
        apr_time_t valid_to;
        apr_time_ansi_put(&valid_to, next_update);
        if (now > valid_to)
        {
            apr_rfc822_date(date_str, valid_to);
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                          "OCSP response has expired at %s!", date_str);
            /* Do not send a stale response */
            ret = GNUTLS_E_OCSP_RESPONSE_ERROR;
            goto resp_cleanup;
        }
    }

    /* What's the actual status? Will be one of
     * gnutls_ocsp_cert_status_t as defined in gnutls/ocsp.h. */
    if (cert_status == GNUTLS_OCSP_CERT_GOOD)
    {
        /* Yay, everything's good! */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                      "CA flagged certificate as valid at %s.", date_str);
    }
    else
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "CA flagged certificate as %s at %s.",
                      cert_status == GNUTLS_OCSP_CERT_REVOKED ?
                      "revoked" : "unknown", date_str);
        ret = GNUTLS_E_OCSP_RESPONSE_ERROR;
    }

 resp_cleanup:
    gnutls_ocsp_resp_deinit(resp);
    return ret;
}



int mgs_get_ocsp_response(gnutls_session_t session __attribute__((unused)),
                          void *ptr,
                          gnutls_datum_t *ocsp_response)
{
    mgs_handle_t *ctxt = (mgs_handle_t *) ptr;
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                  "Loading OCSP response from %s",
                  ctxt->sc->ocsp_response_file);

    int ret = gnutls_load_file(ctxt->sc->ocsp_response_file, ocsp_response);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "Loading OCSP response failed: %s (%d)",
                      gnutls_strerror(ret), ret);
    }
    else
    {
        /* Succeed if response is present and valid. */
        if (check_ocsp_response(ctxt, ocsp_response) == GNUTLS_E_SUCCESS)
            return GNUTLS_E_SUCCESS;
    }

    /* failure, clean up response data */
    gnutls_free(ocsp_response->data);
    ocsp_response->size = 0;
    ocsp_response->data = NULL;
    return GNUTLS_E_NO_CERTIFICATE_STATUS;
}



int mgs_create_ocsp_trust_list(gnutls_x509_trust_list_t *tl,
                               const gnutls_x509_crt_t *chain,
                               const int num)
{
    int added = 0;
    int ret = gnutls_x509_trust_list_init(tl, num);

    if (ret == GNUTLS_E_SUCCESS)
        added = gnutls_x509_trust_list_add_cas(*tl, chain, num, 0);

    if (added != num)
        ret = GNUTLS_E_CERTIFICATE_ERROR;

    /* Clean up trust list in case of error */
    if (ret != GNUTLS_E_SUCCESS)
        gnutls_x509_trust_list_deinit(*tl, 0);

    return ret;
}



apr_status_t mgs_cleanup_trust_list(void *data)
{
    gnutls_x509_trust_list_t *tl = (gnutls_x509_trust_list_t *) data;
    gnutls_x509_trust_list_deinit(*tl, 0);
    return APR_SUCCESS;
}



/*
 * Like in the general post_config hook the HTTP status codes for
 * errors are just for fun. What matters is "neither OK nor DECLINED"
 * to denote an error.
 */
int mgs_ocsp_post_config_server(apr_pool_t *pconf, server_rec *server)
{
    mgs_srvconf_rec *sc =
        (mgs_srvconf_rec *) ap_get_module_config(server->module_config,
                                                 &gnutls_module);

    if (sc->certs_x509_chain_num < 2)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, server,
                     "OCSP stapling is enabled but no CA certificate "
                     "available, make sure it is included in "
                     "GnuTLSCertificateFile!");
        return HTTP_NOT_FOUND;
    }
    sc->ocsp_trust = apr_palloc(pconf,
                                sizeof(gnutls_x509_trust_list_t));
     /* Only the direct issuer may sign the OCSP response or an OCSP
      * signer. */
    int ret = mgs_create_ocsp_trust_list(sc->ocsp_trust,
                                         &(sc->certs_x509_crt_chain[1]),
                                         1);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, server,
                     "Could not create OCSP trust list: %s (%d)",
                     gnutls_strerror(ret), ret);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* deinit trust list when the config pool is destroyed */
    apr_pool_cleanup_register(pconf, sc->ocsp_trust,
                              mgs_cleanup_trust_list,
                              apr_pool_cleanup_null);

    return OK;
}

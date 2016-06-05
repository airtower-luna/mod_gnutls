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
#include "gnutls_cache.h"

#include <apr_lib.h>
#include <apr_time.h>
#include <gnutls/ocsp.h>
#include <time.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif



#define _log_one_ocsp_fail(str, srv)                                    \
    ap_log_error(APLOG_MARK, APLOG_INFO, APR_EGENERAL, (srv),           \
                 "Reason for failed OCSP response verification: %s", (str))
/*
 * Log all matching reasons for verification failure
 */
static void _log_verify_fail_reason(const unsigned int verify, server_rec *s)
{
    if (verify & GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND)
        _log_one_ocsp_fail("Signer cert not found", s);

    if (verify & GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR)
        _log_one_ocsp_fail("Signer cert keyusage error", s);

    if (verify & GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER)
        _log_one_ocsp_fail("Signer cert is not trusted", s);

    if (verify & GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM)
        _log_one_ocsp_fail("Insecure algorithm", s);

    if (verify & GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE)
        _log_one_ocsp_fail("Signature failure", s);

    if (verify & GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED)
        _log_one_ocsp_fail("Signer cert not yet activated", s);

    if (verify & GNUTLS_OCSP_VERIFY_CERT_EXPIRED)
        _log_one_ocsp_fail("Signer cert expired", s);
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
 * Check if the provided OCSP response is usable for stapling in
 * connections to this server. Returns GNUTLS_E_SUCCESS if yes.
 *
 * Supports only one certificate status per response.
 */
int check_ocsp_response(server_rec *s, const gnutls_datum_t *ocsp_response)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    if (sc->ocsp_trust == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "No OCSP trust list available for server \"%s\"!",
                     s->server_hostname);
        return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

    gnutls_ocsp_resp_t resp;
    int ret = gnutls_ocsp_resp_init(&resp);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "Could not initialize OCSP response structure: %s (%d)",
                     gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }
    ret = gnutls_ocsp_resp_import(resp, ocsp_response);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "Importing OCSP response failed: %s (%d)",
                     gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }

    ret = gnutls_ocsp_resp_check_crt(resp, 0, sc->certs_x509_crt_chain[0]);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "OCSP response is not for server certificate: %s (%d)",
                     gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }

    unsigned int verify;
    ret = gnutls_ocsp_resp_verify(resp, *(sc->ocsp_trust), &verify, 0);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "OCSP response verification failed: %s (%d)",
                     gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }
    else
    {
        /* verification worked, check the result */
        if (verify != 0)
        {
            _log_verify_fail_reason(verify, s);
            ret = GNUTLS_E_OCSP_RESPONSE_ERROR;
            goto resp_cleanup;
        }
        else
            ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
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
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
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
        ap_log_error(APLOG_MARK, APLOG_WARNING, APR_EGENERAL, s,
                     "OSCP response claims to be from future (%s), check "
                     "time synchronization!", date_str);
    }

    if (next_update == (time_t) -1)
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s,
                     "OSCP response does not contain nextUpdate info.");
    else
    {
        apr_time_t valid_to;
        apr_time_ansi_put(&valid_to, next_update);
        if (now > valid_to)
        {
            apr_rfc822_date(date_str, valid_to);
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                     "CA flagged certificate as valid at %s.", date_str);
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "CA flagged certificate as %s at %s.",
                     cert_status == GNUTLS_OCSP_CERT_REVOKED ?
                     "revoked" : "unknown", date_str);
        ret = GNUTLS_E_OCSP_RESPONSE_ERROR;
    }

 resp_cleanup:
    gnutls_ocsp_resp_deinit(resp);
    return ret;
}



/*
 * Returns the certificate fingerprint, memory is allocated from p.
 */
static gnutls_datum_t mgs_get_cert_fingerprint(apr_pool_t *p,
                                               gnutls_x509_crt_t cert)
{
    gnutls_datum_t fingerprint = {NULL, 0};
    size_t fplen;
    gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA1, NULL, &fplen);
    unsigned char * fp = apr_palloc(p, fplen);
    gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA1, fp, &fplen);
    /* Safe integer type conversion: The types of fingerprint.size
     * (unsigned int) and fplen (size_t) may have different
     * lengths. */
    if (__builtin_add_overflow(fplen, 0, &fingerprint.size))
        fingerprint.size = 0;
    else
        fingerprint.data = fp;
    return fingerprint;
}



/* TODO: response should be fetched from sc->ocsp_uri */
apr_status_t mgs_cache_ocsp_response(server_rec *s)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    if (sc->cache_type != mgs_cache_dbm && sc->cache_type != mgs_cache_gdbm)
    {
        /* experimental OCSP cache requires DBM cache */
        return APR_ENOTIMPL;
    }

    apr_pool_t *tmp;
    apr_status_t rv = apr_pool_create(&tmp, NULL);

    /* the fingerprint will be used as cache key */
    gnutls_datum_t fingerprint =
        mgs_get_cert_fingerprint(tmp, sc->certs_x509_crt_chain[0]);
    if (fingerprint.data == NULL)
        return APR_EINVAL;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                 "Loading OCSP response from %s",
                 sc->ocsp_response_file);
    apr_file_t *file;
    apr_finfo_t finfo;
    apr_size_t br = 0;
    rv = apr_file_open(&file, sc->ocsp_response_file,
                       APR_READ | APR_BINARY, APR_OS_DEFAULT, tmp);
    if (rv != APR_SUCCESS)
    {
        apr_pool_destroy(tmp);
        return rv;
    }
    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, file);
    if (rv != APR_SUCCESS)
    {
        apr_pool_destroy(tmp);
        return rv;
    }

    gnutls_datum_t resp;
    resp.data = apr_palloc(tmp, finfo.size);
    rv = apr_file_read_full(file, resp.data, finfo.size, &br);
    if (rv != APR_SUCCESS)
    {
        apr_pool_destroy(tmp);
        return rv;
    }
    apr_file_close(file);
    /* safe integer type conversion */
    if (__builtin_add_overflow(br, 0, &resp.size))
    {
        apr_pool_destroy(tmp);
        return APR_EINVAL;
    }

    if (check_ocsp_response(s, &resp) != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, s,
                     "OCSP response validation failed, cannot "
                     "update cache.");
        apr_pool_destroy(tmp);
        return APR_EGENERAL;
    }

    /* TODO: make cache lifetime configurable, make sure expiration
     * happens without storing new data */
    int r = dbm_cache_store(s, fingerprint,
                            resp, apr_time_now() + apr_time_from_sec(120));
    /* destroy pool, and original copy of the OCSP response with it */
    apr_pool_destroy(tmp);
    if (r != 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                      "Storing OCSP response in cache failed.");
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}



int mgs_get_ocsp_response(gnutls_session_t session __attribute__((unused)),
                          void *ptr,
                          gnutls_datum_t *ocsp_response)
{
    mgs_handle_t *ctxt = (mgs_handle_t *) ptr;

    gnutls_datum_t fingerprint =
        mgs_get_cert_fingerprint(ctxt->c->pool,
                                 ctxt->sc->certs_x509_crt_chain[0]);
    if (fingerprint.data == NULL)
        return GNUTLS_E_NO_CERTIFICATE_STATUS;

    *ocsp_response = dbm_cache_fetch(ctxt, fingerprint);
    if (ocsp_response->size == 0)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "Fetching OCSP response from cache failed.");
    }
    else
    {
        /* Succeed if response is present and valid. */
        if (check_ocsp_response(ctxt->c->base_server, ocsp_response)
            == GNUTLS_E_SUCCESS)
            return GNUTLS_E_SUCCESS;
    }
    /* get rid of invalid response (if any) */
    gnutls_free(ocsp_response->data);
    ocsp_response->data = NULL;

    /* If the cache had no response or an invalid one, try to update. */
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                  "No valid OCSP response in cache, trying to update.");
    apr_status_t rv = mgs_cache_ocsp_response(ctxt->c->base_server);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, ctxt->c,
                      "Updating OCSP response cache failed");
        goto fail_cleanup;
    }

    /* retry reading from cache */
    *ocsp_response = dbm_cache_fetch(ctxt, fingerprint);
    if (ocsp_response->size == 0)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "Fetching OCSP response from cache failed on retry.");
    }
    else
    {
        /* Succeed if response is present and valid. */
        if (check_ocsp_response(ctxt->c->base_server, ocsp_response)
            == GNUTLS_E_SUCCESS)
            return GNUTLS_E_SUCCESS;
    }

    /* failure, clean up response data */
 fail_cleanup:
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



apr_uri_t * mgs_cert_get_ocsp_uri(apr_pool_t *p, gnutls_x509_crt_t cert)
{
    apr_pool_t *tmp;
    apr_status_t rv = apr_pool_create(&tmp, p);
    if (rv != APR_SUCCESS)
        return NULL;

    apr_uri_t *ocsp_uri = NULL;

    int ret = GNUTLS_E_SUCCESS;
    /* search authority info access for OCSP URI */
    for (int seq = 0; ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE; seq++)
    {
        gnutls_datum_t ocsp_access_data;
        ret = gnutls_x509_crt_get_authority_info_access(cert, seq,
                                                        GNUTLS_IA_OCSP_URI,
                                                        &ocsp_access_data,
                                                        NULL);
        if (ret == GNUTLS_E_SUCCESS)
        {
            /* create NULL terminated string */
            char *ocsp_str =
                apr_pstrndup(tmp, (const char*) ocsp_access_data.data,
                             ocsp_access_data.size);
            gnutls_free(ocsp_access_data.data);

            ocsp_uri = apr_palloc(p, sizeof(apr_uri_t));
            rv = apr_uri_parse(p, ocsp_str, ocsp_uri);
            if (rv == APR_SUCCESS)
                break;
            else
                ocsp_uri = NULL;
        }
    }

    apr_pool_destroy(tmp);
    return ocsp_uri;
}



/*
 * Like in the general post_config hook the HTTP status codes for
 * errors are just for fun. What matters is "neither OK nor DECLINED"
 * to denote an error.
 */
int mgs_ocsp_post_config_server(apr_pool_t *pconf,
                                apr_pool_t *ptemp __attribute__((unused)),
                                server_rec *server)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(server->module_config, &gnutls_module);

    if (sc->certs_x509_chain_num < 2)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, server,
                     "OCSP stapling is enabled but no CA certificate "
                     "available for %s:%d, make sure it is included in "
                     "GnuTLSCertificateFile!",
                     server->server_hostname, server->addrs->host_port);
        return HTTP_NOT_FOUND;
    }

    sc->ocsp_uri = mgs_cert_get_ocsp_uri(pconf, sc->certs_x509_crt_chain[0]);

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

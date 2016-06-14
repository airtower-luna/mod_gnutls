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
#include "gnutls_util.h"

#include <apr_escape.h>
#include <apr_lib.h>
#include <apr_time.h>
#include <gnutls/ocsp.h>
#include <time.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

/* maximum supported OCSP response size, 8K should be plenty */
#define OCSP_RESP_SIZE_MAX (8 * 1024)
#define OCSP_REQ_TYPE "application/ocsp-request"
#define OCSP_RESP_TYPE "application/ocsp-response"



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
 * Create an OCSP request for the certificate of the given server. The
 * DER encoded request is stored in 'req' (must be released with
 * gnutls_free() when no longer needed), its nonce in 'nonce' (same,
 * if not NULL).
 *
 * Returns GNUTLS_E_SUCCESS, or a GnuTLS error code.
 */
static int mgs_create_ocsp_request(server_rec *s, gnutls_datum_t *req,
                            gnutls_datum_t *nonce)
    __attribute__((nonnull(1, 2)));
static int mgs_create_ocsp_request(server_rec *s, gnutls_datum_t *req,
                            gnutls_datum_t *nonce)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    gnutls_ocsp_req_t r;
    int ret = gnutls_ocsp_req_init(&r);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "Could not initialize OCSP request structure: %s (%d)",
                     gnutls_strerror(ret), ret);
        return ret;
    }

    /* GnuTLS doc says that the digest is "normally"
     * GNUTLS_DIG_SHA1. */
    ret = gnutls_ocsp_req_add_cert(r, GNUTLS_DIG_SHA256,
                                   sc->certs_x509_crt_chain[1],
                                   sc->certs_x509_crt_chain[0]);

    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "Adding certificate to OCSP request for %s:%d "
                     "failed: %s (%d)",
                     s->server_hostname, s->addrs->host_port,
                     gnutls_strerror(ret), ret);
        gnutls_ocsp_req_deinit(r);
        return ret;
    }

    ret = gnutls_ocsp_req_randomize_nonce(r);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "OCSP nonce creation failed: %s (%d)",
                     gnutls_strerror(ret), ret);
        gnutls_ocsp_req_deinit(r);
        return ret;
    }

    if (nonce != NULL)
    {
        ret = gnutls_ocsp_req_get_nonce(r, NULL, nonce);
        if (ret != GNUTLS_E_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                         "Could not get nonce: %s (%d)",
                         gnutls_strerror(ret), ret);
            gnutls_free(nonce->data);
            nonce->data = NULL;
            nonce->size = 0;
            gnutls_ocsp_req_deinit(r);
            return ret;
        }
    }

    ret = gnutls_ocsp_req_export(r, req);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "OCSP request export failed: %s (%d)",
                     gnutls_strerror(ret), ret);
        gnutls_free(req->data);
        req->data = NULL;
        req->size = 0;
        if (nonce != NULL)
        {
            gnutls_free(nonce->data);
            nonce->data = NULL;
            nonce->size = 0;
        }
        gnutls_ocsp_req_deinit(r);
        return ret;
    }

    gnutls_ocsp_req_deinit(r);
    return ret;
}



/**
 * Check if the provided OCSP response is usable for stapling in
 * connections to this server. Returns GNUTLS_E_SUCCESS if yes.
 *
 * Supports only one certificate status per response.
 *
 * If expiry is not NULL, it will be set to the nextUpdate time
 * contained in the response, or zero if the response does not contain
 * a nextUpdate field.
 */
int check_ocsp_response(server_rec *s, const gnutls_datum_t *ocsp_response,
                        apr_time_t* expiry)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    if (sc->ocsp->trust == NULL)
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
    ret = gnutls_ocsp_resp_verify(resp, *(sc->ocsp->trust), &verify, 0);
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
    {
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s,
                     "OSCP response does not contain nextUpdate info.");
        if (expiry != NULL)
            *expiry = 0;
    }
    else
    {
        apr_time_t valid_to;
        apr_time_ansi_put(&valid_to, next_update);
        if (expiry != NULL)
            *expiry = valid_to;
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



static apr_status_t do_ocsp_request(apr_pool_t *p, server_rec *s,
                                    gnutls_datum_t *request,
                                    gnutls_datum_t *response)
    __attribute__((nonnull));
static apr_status_t do_ocsp_request(apr_pool_t *p, server_rec *s,
                                    gnutls_datum_t *request,
                                    gnutls_datum_t *response)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    if (apr_strnatcmp(sc->ocsp->uri->scheme, "http"))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "Scheme \"%s\" is not supported for OCSP requests!",
                     sc->ocsp->uri->scheme);
        return APR_EINVAL;
    }

    const char* header = http_post_header(p, sc->ocsp->uri,
                                          OCSP_REQ_TYPE, OCSP_RESP_TYPE,
                                          request->size);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                 "OCSP POST header: %s", header);

    /* Find correct port */
    apr_port_t port = sc->ocsp->uri->port ?
        sc->ocsp->uri->port : apr_uri_port_of_scheme(sc->ocsp->uri->scheme);

    apr_sockaddr_t *sa;
    apr_status_t rv = apr_sockaddr_info_get(&sa, sc->ocsp->uri->hostname,
                                            APR_UNSPEC, port, 0, p);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Address resolution for OCSP responder %s failed.",
                     sc->ocsp->uri->hostinfo);
    }

    /* There may be multiple answers, try them in order until one
     * works. */
    apr_socket_t *sock;
    /* TODO: configurable timeout */
    apr_interval_time_t timeout = apr_time_from_sec(2);
    while (sa)
    {
        rv = apr_socket_create(&sock, sa->family, SOCK_STREAM,
                               APR_PROTO_TCP, p);
        if (rv == APR_SUCCESS)
        {
            apr_socket_timeout_set(sock, timeout);
            rv = apr_socket_connect(sock, sa);
            if (rv == APR_SUCCESS)
                /* Connected! */
                break;
            apr_socket_close(sock);
        }
        sa = sa->next;
    }
    /* If the socket is connected, 'sa' points at the matching
     * address. */
    if (sa == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Connecting to OCSP responder %s failed.",
                     sc->ocsp->uri->hostinfo);
        return rv;
    }

    /* Header is generated locally, so strlen() is safe. */
    rv = sock_send_buf(sock, header, strlen(header));
    if (rv == APR_SUCCESS)
        rv = sock_send_buf(sock, (char*) request->data, request->size);
    /* catches errors from both header and request */
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Sending OCSP request failed.");
        goto exit;
    }

    /* Prepare bucket brigades to read the response header. BBs make
     * it easy to split the header into lines. */
    apr_bucket_alloc_t *ba = apr_bucket_alloc_create(p);
    apr_bucket_brigade *bb = apr_brigade_create(p, ba);
    /* will carry split response headers */
    apr_bucket_brigade *rh = apr_brigade_create(p, ba);

    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_socket_create(sock, ba));
    /* The first line in the response header must be the status, check
     * for OK status code. Line looks similar to "HTTP/1.0 200 OK". */
    const char *h = read_line(p, bb, rh);
    const char *code = 0;
    if (h == NULL
        || strncmp(h, "HTTP/", 5)
        || (code = ap_strchr(h, ' ')) == NULL
        || apr_atoi64(code + 1) != HTTP_OK)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Invalid HTTP response status from %s: %s",
                     sc->ocsp->uri->hostinfo, h);
        rv = APR_ECONNRESET;
        goto exit;
    }
    /* Read remaining header lines */
    for (h = read_line(p, bb, rh); h != NULL && apr_strnatcmp(h, "") != 0;
         h = read_line(p, bb, rh))
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, APR_SUCCESS, s,
                     "Received header: %s", h);
    }
    /* The last header line should be empty (""), NULL indicates an
     * error. */
    if (h == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Error while reading HTTP response header from %s",
                     sc->ocsp->uri->hostinfo);
        rv = APR_ECONNRESET;
        goto exit;
    }

    /* Headers have been consumed, the rest of the available data
     * should be the actual response. */
    apr_size_t len = OCSP_RESP_SIZE_MAX;
    char buf[OCSP_RESP_SIZE_MAX];
    /* apr_brigade_pflatten() can allocate directly from the pool, but
     * the documentation does not describe a way to limit the size of
     * the buffer, which is necessary here to prevent DoS by endless
     * response. Use apr_brigade_flatten() to read to a stack pool,
     * then create a copy to return. */
    rv = apr_brigade_flatten(bb, buf, &len);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Failed to read OCSP response.");
        goto exit;
    }

    /* With the length restriction this really should not happen. */
    if (__builtin_add_overflow(len, 0, &response->size))
    {
        response->data = NULL;
        rv = APR_ENOMEM;
    }
    else
    {
        response->data = apr_pmemdup(p, buf, len);
    }

 exit:
    apr_socket_close(sock);
    return rv;
}



apr_status_t mgs_cache_ocsp_response(server_rec *s)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    if (sc->cache == NULL)
    {
        /* OCSP caching requires a cache. */
        return APR_ENOTIMPL;
    }

    apr_pool_t *tmp;
    apr_status_t rv = apr_pool_create(&tmp, NULL);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "could not create temporary pool for %s",
                     __func__);
        return rv;
    }

    gnutls_datum_t req;
    int ret = mgs_create_ocsp_request(s, &req, NULL);
    if (ret == GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                     "created OCSP request for %s:%d: %s",
                     s->server_hostname, s->addrs->host_port,
                     apr_pescape_hex(tmp, req.data, req.size, 0));
        gnutls_free(req.data);
    }

    gnutls_datum_t resp;
    rv = do_ocsp_request(tmp, s, &req, &resp);
    if (rv != APR_SUCCESS)
    {
        /* do_ocsp_request() does its own error logging. */
        apr_pool_destroy(tmp);
        return rv;
    }
    /* TODO: check nonce */

    /* TODO: separate option to enable/disable OCSP stapling, restore
     * reading response from file for debugging/expert use. */

    apr_time_t expiry;
    if (check_ocsp_response(s, &resp, &expiry) != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, s,
                     "OCSP response validation failed, cannot "
                     "update cache.");
        apr_pool_destroy(tmp);
        return APR_EGENERAL;
    }
    /* If expiry is zero, the response does not contain a nextUpdate
     * field. Use the default cache timeout. */
    if (expiry == 0)
        expiry = apr_time_now() + sc->cache_timeout;
    /* Apply grace time otherwise. */
    else
        expiry -= sc->ocsp_grace_time;

    int r = sc->cache->store(s, sc->ocsp->fingerprint, resp, expiry);
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
    if (ctxt->sc->cache == NULL)
    {
        /* OCSP caching requires a cache. */
        return GNUTLS_E_NO_CERTIFICATE_STATUS;
    }

    *ocsp_response = ctxt->sc->cache->fetch(ctxt,
                                            ctxt->sc->ocsp->fingerprint);
    if (ocsp_response->size == 0)
    {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, ctxt->c,
                      "Fetching OCSP response from cache failed.");
    }
    else
    {
        return GNUTLS_E_SUCCESS;
    }
    /* get rid of invalid response (if any) */
    gnutls_free(ocsp_response->data);
    ocsp_response->data = NULL;

    /* If the cache had no response or an invalid one, try to update. */
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                  "No valid OCSP response in cache, trying to update.");

    /* TODO: Once sending OCSP requests is implemented we need a rate
     * limit for retries on error. If the responder is overloaded or
     * buggy we don't want to add too much more load, and if a MITM is
     * messing with requests a repetition loop might end up being a
     * self-inflicted denial of service. */
    apr_status_t rv = apr_global_mutex_trylock(ctxt->sc->ocsp_mutex);
    if (APR_STATUS_IS_EBUSY(rv))
    {
        /* Another thread is currently holding the mutex, wait. */
        apr_global_mutex_lock(ctxt->sc->ocsp_mutex);
        /* Check if this other thread updated the response we need. It
         * would be better to have a vhost specific mutex, but at the
         * moment there's no good way to integrate that with the
         * Apache Mutex directive. */
        *ocsp_response = ctxt->sc->cache->fetch(ctxt,
                                                ctxt->sc->ocsp->fingerprint);
        if (ocsp_response->size > 0)
        {
            /* Got a valid response now, unlock mutex and return. */
            apr_global_mutex_unlock(ctxt->sc->ocsp_mutex);
            return GNUTLS_E_SUCCESS;
        }
        else
        {
            gnutls_free(ocsp_response->data);
            ocsp_response->data = NULL;
        }
    }

    rv = mgs_cache_ocsp_response(ctxt->c->base_server);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, ctxt->c,
                      "Updating OCSP response cache failed");
        apr_global_mutex_unlock(ctxt->sc->ocsp_mutex);
        goto fail_cleanup;
    }
    apr_global_mutex_unlock(ctxt->sc->ocsp_mutex);

    /* retry reading from cache */
    *ocsp_response = ctxt->sc->cache->fetch(ctxt,
                                            ctxt->sc->ocsp->fingerprint);
    if (ocsp_response->size == 0)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "Fetching OCSP response from cache failed on retry.");
    }
    else
    {
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

    sc->ocsp = apr_palloc(pconf, sizeof(struct mgs_ocsp_data));

    sc->ocsp->fingerprint =
        mgs_get_cert_fingerprint(pconf, sc->certs_x509_crt_chain[0]);
    if (sc->ocsp->fingerprint.data == NULL)
        return HTTP_INTERNAL_SERVER_ERROR;

    sc->ocsp->uri = mgs_cert_get_ocsp_uri(pconf,
                                          sc->certs_x509_crt_chain[0]);

    sc->ocsp->trust = apr_palloc(pconf,
                                 sizeof(gnutls_x509_trust_list_t));
     /* Only the direct issuer may sign the OCSP response or an OCSP
      * signer. */
    int ret = mgs_create_ocsp_trust_list(sc->ocsp->trust,
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
    apr_pool_cleanup_register(pconf, sc->ocsp->trust,
                              mgs_cleanup_trust_list,
                              apr_pool_cleanup_null);

    return OK;
}

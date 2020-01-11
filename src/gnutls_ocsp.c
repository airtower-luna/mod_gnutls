/*
 *  Copyright 2016-2020 Fiona Klute
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
#include "gnutls_config.h"
#include "gnutls_util.h"
#include "gnutls_watchdog.h"

#include <apr_escape.h>
#include <apr_lib.h>
#include <apr_time.h>
#include <gnutls/crypto.h>
#include <gnutls/ocsp.h>
#include <mod_watchdog.h>
#include <time.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

/** maximum supported OCSP response size, 8K should be plenty */
#define OCSP_RESP_SIZE_MAX (8 * 1024)
#define OCSP_REQ_TYPE "application/ocsp-request"
#define OCSP_RESP_TYPE "application/ocsp-response"

/** Dummy data for failure cache entries (one byte). */
#define OCSP_FAILURE_CACHE_DATA 0x0f
/** Macro to check if an OCSP reponse pointer contains a cached
 * failure */
#define IS_FAILURE_RESPONSE(resp) \
    (((resp)->size == sizeof(unsigned char)) &&                     \
     (*((unsigned char *) (resp)->data) == OCSP_FAILURE_CACHE_DATA))


#define _log_one_ocsp_fail(str, srv)                                    \
    ap_log_error(APLOG_MARK, APLOG_INFO, APR_EGENERAL, (srv),           \
                 "Reason for failed OCSP response verification: %s", (str))
/**
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



const char *mgs_ocsp_stapling_enable(cmd_parms *parms,
                                     void *dummy __attribute__((unused)),
                                     const int arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    if (arg)
        sc->ocsp_staple = GNUTLS_ENABLED_TRUE;
    else
        sc->ocsp_staple = GNUTLS_ENABLED_FALSE;

    return NULL;
}



const char *mgs_set_ocsp_auto_refresh(cmd_parms *parms,
                                      void *dummy __attribute__((unused)),
                                      const int arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    if (arg)
        sc->ocsp_auto_refresh = GNUTLS_ENABLED_TRUE;
    else
        sc->ocsp_auto_refresh = GNUTLS_ENABLED_FALSE;

    return NULL;
}



const char *mgs_set_ocsp_check_nonce(cmd_parms *parms,
                                     void *dummy __attribute__((unused)),
                                     const int arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    if (arg)
        sc->ocsp_check_nonce = GNUTLS_ENABLED_TRUE;
    else
        sc->ocsp_check_nonce = GNUTLS_ENABLED_FALSE;

    return NULL;
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
 * @param s server reference for logging
 *
 * @return GNUTLS_E_SUCCESS, or a GnuTLS error code.
 */
static int mgs_create_ocsp_request(server_rec *s,
                                   struct mgs_ocsp_data *req_data,
                                   gnutls_datum_t *req,
                                   gnutls_datum_t *nonce)
    __attribute__((nonnull(1, 3)));
static int mgs_create_ocsp_request(server_rec *s,
                                   struct mgs_ocsp_data *req_data,
                                   gnutls_datum_t *req,
                                   gnutls_datum_t *nonce)
{
    gnutls_ocsp_req_t r;
    int ret = gnutls_ocsp_req_init(&r);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "Could not initialize OCSP request structure: %s (%d)",
                     gnutls_strerror(ret), ret);
        return ret;
    }

    /* issuer is set to a reference, so musn't be cleaned up */
    gnutls_x509_crt_t issuer;
    ret = gnutls_x509_trust_list_get_issuer(*req_data->trust, req_data->cert,
                                            &issuer, 0);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "Could not get issuer from trust list: %s (%d)",
                     gnutls_strerror(ret), ret);
        gnutls_ocsp_req_deinit(r);
        return ret;
    }

    /* GnuTLS doc says that the digest is "normally"
     * GNUTLS_DIG_SHA1. */
    ret = gnutls_ocsp_req_add_cert(r, GNUTLS_DIG_SHA256,
                                   issuer, req_data->cert);

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
 *
 * If nonce is not NULL, the response must contain a matching nonce.
 */
int check_ocsp_response(server_rec *s, struct mgs_ocsp_data *req_data,
                        const gnutls_datum_t *ocsp_response,
                        apr_time_t* expiry, const gnutls_datum_t *nonce)
    __attribute__((nonnull(1, 3)));
int check_ocsp_response(server_rec *s, struct mgs_ocsp_data *req_data,
                        const gnutls_datum_t *ocsp_response,
                        apr_time_t* expiry, const gnutls_datum_t *nonce)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    if (req_data->trust == NULL)
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

    ret = gnutls_ocsp_resp_check_crt(resp, 0, req_data->cert);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "OCSP response is not for server certificate: %s (%d)",
                     gnutls_strerror(ret), ret);
        goto resp_cleanup;
    }

    unsigned int verify;
    ret = gnutls_ocsp_resp_verify(resp, *(req_data->trust), &verify, 0);
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
            ap_log_error(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, s,
                         "OCSP response signature is valid.");
    }

    /* Even some large CAs do not support nonces, probably because
     * that way they can cache responses. :-/ */
    if (nonce != NULL && sc->ocsp_check_nonce)
    {
        gnutls_datum_t resp_nonce;
        ret = gnutls_ocsp_resp_get_nonce(resp, 0, &resp_nonce);
        if (ret != GNUTLS_E_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                         "Could not get OCSP response nonce: %s (%d)",
                         gnutls_strerror(ret), ret);
            goto resp_cleanup;
        }
        if (resp_nonce.size != nonce->size
            || memcmp(resp_nonce.data, nonce->data, nonce->size))
        {
            ret = GNUTLS_E_OCSP_RESPONSE_ERROR;
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                         "OCSP response invalid: nonce mismatch");
            gnutls_free(resp_nonce.data);
            goto resp_cleanup;
        }
        ap_log_error(APLOG_MARK, APLOG_TRACE2, APR_SUCCESS, s,
                     "OCSP response: nonce match");
        gnutls_free(resp_nonce.data);
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
    size_t fplen = 0;
    gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA1, NULL, &fplen);
    unsigned char * fp = apr_palloc(p, fplen);
    gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA1, fp, &fplen);
    /* Safe integer type conversion: The types of fingerprint.size
     * (unsigned int) and fplen (size_t) may have different
     * lengths. */
#if defined(__GNUC__) && __GNUC__ < 5 && !defined(__clang__)
    if (__builtin_expect(fplen <= UINT_MAX, 1))
    {
        fingerprint.size = (unsigned int) fplen;
        fingerprint.data = fp;
    }
#else
    if (__builtin_add_overflow(fplen, 0, &fingerprint.size))
        fingerprint.size = 0;
    else
        fingerprint.data = fp;
#endif
    return fingerprint;
}



static apr_status_t do_ocsp_request(apr_pool_t *p, server_rec *s,
                                    apr_uri_t *uri,
                                    gnutls_datum_t *request,
                                    gnutls_datum_t *response)
    __attribute__((nonnull));
static apr_status_t do_ocsp_request(apr_pool_t *p, server_rec *s,
                                    apr_uri_t *uri,
                                    gnutls_datum_t *request,
                                    gnutls_datum_t *response)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    if (apr_strnatcmp(uri->scheme, "http"))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "Scheme \"%s\" is not supported for OCSP requests!",
                     uri->scheme);
        return APR_EINVAL;
    }

    const char* header = http_post_header(p, uri,
                                          OCSP_REQ_TYPE, OCSP_RESP_TYPE,
                                          request->size);
    ap_log_error(APLOG_MARK, APLOG_TRACE2, APR_SUCCESS, s,
                 "OCSP POST header: %s", header);

    /* Find correct port */
    apr_port_t port = uri->port ?
        uri->port : apr_uri_port_of_scheme(uri->scheme);

    apr_sockaddr_t *sa;
    apr_status_t rv = apr_sockaddr_info_get(&sa, uri->hostname,
                                            APR_UNSPEC, port, 0, p);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Address resolution for OCSP responder %s failed.",
                     uri->hostinfo);
    }

    /* There may be multiple answers, try them in order until one
     * works. */
    apr_socket_t *sock;
    while (sa)
    {
        rv = apr_socket_create(&sock, sa->family, SOCK_STREAM,
                               APR_PROTO_TCP, p);
        if (rv == APR_SUCCESS)
        {
            apr_socket_timeout_set(sock, sc->ocsp_socket_timeout);
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
                     uri->hostinfo);
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
                     uri->hostinfo, h);
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
                     uri->hostinfo);
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

    /* With the length restriction this really should not overflow. */
#if defined(__GNUC__) && __GNUC__ < 5 && !defined(__clang__)
    if (__builtin_expect(len > UINT_MAX, 0))
#else
    if (__builtin_add_overflow(len, 0, &response->size))
#endif
    {
        response->data = NULL;
        rv = APR_ENOMEM;
    }
    else
    {
#if defined(__GNUC__) && __GNUC__ < 5 && !defined(__clang__)
        response->size = (unsigned int) len;
#endif
        response->data = apr_pmemdup(p, buf, len);
    }

 exit:
    apr_socket_close(sock);
    return rv;
}



/**
 * Get a fresh OCSP response and put it into the cache.
 *
 * @param s server that needs a new response
 *
 * @param req_data struct describing the certificate for which to
 * cache a response
 *
 * @param cache_expiry If not `NULL`, this `apr_time_t` will be set to
 * the expiration time of the cache entry. Remains unchanged on
 * failure.
 *
 * @return APR_SUCCESS or an APR error code
 */
static apr_status_t mgs_cache_ocsp_response(server_rec *s,
                                            struct mgs_ocsp_data *req_data,
                                            apr_time_t *cache_expiry)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    if (sc->ocsp_cache == NULL)
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

    gnutls_datum_t resp;
    gnutls_datum_t nonce = { NULL, 0 };

    if (sc->ocsp_response_file != NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                     "Loading OCSP response from %s",
                     sc->ocsp_response_file);
        rv = datum_from_file(tmp, sc->ocsp_response_file, &resp);
        if (rv != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Loading OCSP response from %s failed!",
                         sc->ocsp_response_file);
            apr_pool_destroy(tmp);
            return rv;
        }
    }
    else
    {
        gnutls_datum_t req;
        int ret = mgs_create_ocsp_request(s, req_data, &req, &nonce);
        if (ret == GNUTLS_E_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE2, APR_SUCCESS, s,
                         "created OCSP request for %s:%d: %s",
                         s->server_hostname, s->addrs->host_port,
                         apr_pescape_hex(tmp, req.data, req.size, 0));
        }
        else
        {
            gnutls_free(req.data);
            gnutls_free(nonce.data);
            apr_pool_destroy(tmp);
            return APR_EGENERAL;
        }

        rv = do_ocsp_request(tmp, s, req_data->uri, &req, &resp);
        gnutls_free(req.data);
        if (rv != APR_SUCCESS)
        {
            /* do_ocsp_request() does its own error logging. */
            gnutls_free(nonce.data);
            apr_pool_destroy(tmp);
            return rv;
        }
    }

    apr_time_t next_update;
    if (check_ocsp_response(s, req_data, &resp, &next_update,
                            nonce.size ? &nonce : NULL)
        != GNUTLS_E_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, s,
                     "OCSP response validation failed, cannot "
                     "update cache.");
        apr_pool_destroy(tmp);
        gnutls_free(nonce.data);
        return APR_EGENERAL;
    }
    gnutls_free(nonce.data);

    apr_time_t expiry = apr_time_now() + sc->ocsp_cache_time;
    /* Make sure that a response is not cached beyond its nextUpdate
     * time. If the variable next_update is zero, the response does
     * not contain a nextUpdate field. */
    if (next_update != 0 && next_update < expiry)
    {
        char date_str[APR_RFC822_DATE_LEN];
        apr_rfc822_date(date_str, next_update);
        ap_log_error(APLOG_MARK, APLOG_WARNING, APR_EGENERAL, s,
                     "OCSP response timeout restricted to nextUpdate time %s. "
                     "Check if GnuTLSOCSPCacheTimeout is appropriate.",
                     date_str);
        expiry = next_update;
    }

    int r = mgs_cache_store(sc->ocsp_cache, s,
                            req_data->fingerprint, resp, expiry);
    /* destroy pool, and original copy of the OCSP response with it */
    apr_pool_destroy(tmp);
    if (r != 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                      "Storing OCSP response in cache failed.");
        return APR_EGENERAL;
    }

    if (cache_expiry != NULL)
        *cache_expiry = expiry;
    return APR_SUCCESS;
}



/**
 * Retries after failed OCSP requests must be rate limited. If the
 * responder is overloaded or buggy we don't want to add too much more
 * load, and if a MITM is messing with requests a repetition loop
 * might end up being a self-inflicted denial of service. This
 * function writes a specially formed entry to the cache to indicate a
 * recent failure.
 *
 * @param s the server for which an OCSP request failed
 *
 * @param req_data OCSP data structure for the certificate that could
 * not be checked
 *
 * @param timeout lifetime of the cache entry
 */
static void mgs_cache_ocsp_failure(server_rec *s,
                                   struct mgs_ocsp_data *req_data,
                                   apr_interval_time_t timeout)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(s->module_config, &gnutls_module);

    unsigned char c = OCSP_FAILURE_CACHE_DATA;
    gnutls_datum_t dummy = {
        .data = &c,
        .size = sizeof(c)
    };
    apr_time_t expiry = apr_time_now() + timeout;

    int r = mgs_cache_store(sc->ocsp_cache, s,
                            req_data->fingerprint, dummy, expiry);
    if (r != 0)
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                     "Caching OCSP failure failed.");
}



int mgs_get_ocsp_response(mgs_handle_t *ctxt,
                          struct mgs_ocsp_data *req_data,
                          gnutls_datum_t *ocsp_response)
{
    mgs_srvconf_rec *sc = ctxt->sc;

    if (!sc->ocsp_staple || sc->ocsp_cache == NULL)
    {
        /* OCSP must be enabled and caching requires a cache. */
        return GNUTLS_E_NO_CERTIFICATE_STATUS;
    }

    // TODO: Large allocation, and the pool system doesn't offer realloc
    ocsp_response->data = apr_palloc(ctxt->c->pool, OCSP_RESP_SIZE_MAX);
    ocsp_response->size = OCSP_RESP_SIZE_MAX;

    apr_status_t rv = mgs_cache_fetch(sc->ocsp_cache,
                                      ctxt->c->base_server,
                                      req_data->fingerprint,
                                      ocsp_response,
                                      ctxt->c->pool);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, APR_EGENERAL, ctxt->c,
                      "Fetching OCSP response from cache failed.");
    }
    else if (IS_FAILURE_RESPONSE(ocsp_response))
    {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, ctxt->c,
                      "Cached OCSP failure found for %s.",
                      ctxt->c->base_server->server_hostname);
        goto fail_cleanup;
    }
    else
    {
        return GNUTLS_E_SUCCESS;
    }
    /* keep response buffer, reset size for reuse */
    ocsp_response->size = OCSP_RESP_SIZE_MAX;

    /* If the cache had no response or an invalid one, try to update. */
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                  "No valid OCSP response in cache, trying to update.");

    rv = apr_global_mutex_trylock(sc->ocsp_mutex);
    if (APR_STATUS_IS_EBUSY(rv))
    {
        /* Another thread is currently holding the mutex, wait. */
        apr_global_mutex_lock(sc->ocsp_mutex);
        /* Check if this other thread updated the response we need. It
         * would be better to have a vhost specific mutex, but at the
         * moment there's no good way to integrate that with the
         * Apache Mutex directive. */
        rv = mgs_cache_fetch(sc->ocsp_cache,
                             ctxt->c->base_server,
                             req_data->fingerprint,
                             ocsp_response,
                             ctxt->c->pool);
        if (rv == APR_SUCCESS)
        {
            apr_global_mutex_unlock(sc->ocsp_mutex);
            /* Check if the response is valid. */
            if (IS_FAILURE_RESPONSE(ocsp_response))
            {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, ctxt->c,
                              "Cached OCSP failure found for %s.",
                              ctxt->c->base_server->server_hostname);
                goto fail_cleanup;
            }
            else
                return GNUTLS_E_SUCCESS;
        }
        else
        {
            /* keep response buffer, reset size for reuse */
            ocsp_response->size = OCSP_RESP_SIZE_MAX;
        }
    }

    rv = mgs_cache_ocsp_response(ctxt->c->base_server, req_data, NULL);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, ctxt->c,
                      "Caching a fresh OCSP response failed");
        /* cache failure to rate limit retries */
        mgs_cache_ocsp_failure(ctxt->c->base_server,
                               req_data,
                               sc->ocsp_failure_timeout);
        apr_global_mutex_unlock(sc->ocsp_mutex);
        goto fail_cleanup;
    }
    apr_global_mutex_unlock(sc->ocsp_mutex);

    /* retry reading from cache */
    rv = mgs_cache_fetch(sc->ocsp_cache,
                         ctxt->c->base_server,
                         req_data->fingerprint,
                         ocsp_response,
                         ctxt->c->pool);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "Fetching OCSP response from cache failed on retry.");
    }
    else
    {
        return GNUTLS_E_SUCCESS;
    }

    /* failure, reset struct, buffer will be released with the
     * connection pool */
 fail_cleanup:
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



/** The maximum random fuzz base (half the maximum fuzz) that will not
 * overflow. The permitted values are limited to whatever will not
 * make an `apr_interval_time_t` variable overflow when multiplied
 * with `APR_UINT16_MAX`. With apr_interval_time_t being a 64 bit
 * signed integer the maximum fuzz interval is about 4.5 years, which
 * should be more than plenty. */
#define MAX_FUZZ_BASE (APR_INT64_MAX / APR_UINT16_MAX)

/**
 * Perform an asynchronous OCSP cache update. This is a callback for
 * mod_watchdog, so the API is fixed.
 *
 * @param state watchdog state (starting/running/stopping)
 * @param data callback data, contains the server_rec
 * @param pool temporary callback pool destroyed after the call
 * @return always `APR_SUCCESS` as required by the mod_watchdog API to
 * indicate that the callback should be called again
 */
static apr_status_t mgs_async_ocsp_update(int state,
                                          void *data,
                                          apr_pool_t *pool)
{
    /* If the server is stopping there's no need to do an OCSP
     * update. */
    if (state == AP_WATCHDOG_STATE_STOPPING)
        return APR_SUCCESS;

    server_rec *server = (server_rec *) data;
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(server->module_config, &gnutls_module);
    apr_time_t expiry = 0;

    /* Holding the mutex should help avoiding simultaneous synchronous
     * and asynchronous OCSP requests in some edge cases: during
     * startup if there's an early request, and if OCSP requests fail
     * repeatedly until the cached response expires and a synchronous
     * update is triggered before a failure cache entry is
     * created. Usually there should be a good OCSP response in the
     * cache and the mutex is never touched in
     * mgs_get_ocsp_response. */
    apr_global_mutex_lock(sc->ocsp_mutex);
    apr_status_t rv = mgs_cache_ocsp_response(server, sc->ocsp, &expiry);

    apr_interval_time_t next_interval;
    if (rv != APR_SUCCESS)
        next_interval = sc->ocsp_failure_timeout;
    else
    {
        apr_uint16_t random_bytes;
        int res = gnutls_rnd(GNUTLS_RND_NONCE, &random_bytes,
                             sizeof(random_bytes));
        if (__builtin_expect(res < 0, 0))
        {
            /* Shouldn't ever happen, because a working random number
             * generator is required for establishing TLS sessions. */
            random_bytes = (apr_uint16_t) apr_time_now();
            ap_log_error(APLOG_MARK, APLOG_WARNING, APR_EGENERAL, server,
                         "Error getting random number for fuzzy update "
                         "interval: %s Falling back on truncated time.",
                         gnutls_strerror(res));
        }

        /* Choose the fuzz interval for the next update between
         * `sc->ocsp_fuzz_time` and twice that. */
        apr_interval_time_t fuzz = sc->ocsp_fuzz_time
            + (sc->ocsp_fuzz_time * random_bytes / APR_UINT16_MAX);

        /* With an extremly short timeout or weird nextUpdate value
         * next_interval <= 0 might happen. Use the failure timeout to
         * avoid endlessly repeating updates. */
        next_interval = expiry - apr_time_now();
        if (next_interval <= 0)
        {
            next_interval = sc->ocsp_failure_timeout;
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, server,
                         "OCSP cache expiration time of the response for "
                         "%s:%d is in the past, repeating after failure "
                         "timeout (GnuTLSOCSPFailureTimeout).",
                         server->server_hostname, server->addrs->host_port);
        }

        /* It's possible to compare maximum fuzz and configured OCSP
         * cache timeout at configuration time, but the interval until
         * the nextUpdate value expires (or the failure timeout
         * fallback above) might be shorter. Make sure that we don't
         * end up with a negative interval. */
        while (fuzz > next_interval)
            fuzz /= 2;
        next_interval -= fuzz;
    }

    sc->singleton_wd->set_callback_interval(sc->singleton_wd->wd,
                                            next_interval,
                                            server, mgs_async_ocsp_update);

    ap_log_error(APLOG_MARK, rv == APR_SUCCESS ? APLOG_DEBUG : APLOG_WARNING,
                 rv, server,
                 "Async OCSP update %s for %s:%d, next update in "
                 "%" APR_TIME_T_FMT " seconds.",
                 rv == APR_SUCCESS ? "done" : "failed",
                 server->server_hostname, server->addrs->host_port,
                 apr_time_sec(next_interval));

    /* Check if there's still a response in the cache. If not, add a
     * failure entry. If there already is a failure entry, refresh
     * it. The lifetime of such entries is twice the error timeout to
     * make sure they do not expire before the next scheduled
     * update. */
    if (rv != APR_SUCCESS)
    {
        gnutls_datum_t ocsp_response;
        ocsp_response.data = apr_palloc(pool, OCSP_RESP_SIZE_MAX);
        ocsp_response.size = OCSP_RESP_SIZE_MAX;

        apr_status_t rv = mgs_cache_fetch(sc->ocsp_cache, server,
                                          sc->ocsp->fingerprint,
                                          &ocsp_response,
                                          pool);

        if (rv != APR_SUCCESS || (IS_FAILURE_RESPONSE(&ocsp_response)))
        {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, server,
                         "Caching OCSP request failure for %s:%d.",
                         server->server_hostname, server->addrs->host_port);
            mgs_cache_ocsp_failure(server, sc->ocsp,
                                   sc->ocsp_failure_timeout * 2);
        }
    }
    apr_global_mutex_unlock(sc->ocsp_mutex);

    return APR_SUCCESS;
}



const char* mgs_ocsp_configure_stapling(apr_pool_t *pconf,
                                        apr_pool_t *ptemp __attribute__((unused)),
                                        server_rec *server)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(server->module_config, &gnutls_module);

    if (sc->certs_x509_chain_num < 2)
        return "No issuer (CA) certificate available, cannot enable "
            "stapling. Please add it to the GnuTLSCertificateFile.";

    mgs_ocsp_data_t ocsp = apr_palloc(pconf, sizeof(struct mgs_ocsp_data));

    ocsp->cert = sc->certs_x509_crt_chain[0];
    ocsp->uri = mgs_cert_get_ocsp_uri(pconf, ocsp->cert);
    if (ocsp->uri == NULL && sc->ocsp_response_file == NULL)
        return "No OCSP URI in the certificate nor a GnuTLSOCSPResponseFile "
            "setting, cannot configure OCSP stapling.";

    if (sc->ocsp_cache == NULL)
        return "No OCSP response cache available, please check "
            "the GnuTLSOCSPCache setting.";

    sc->ocsp = ocsp;
    return NULL;
}



/*
 * Like in the general post_config hook the HTTP status codes for
 * errors are just for fun. What matters is "neither OK nor DECLINED"
 * to denote an error.
 */
int mgs_ocsp_enable_stapling(apr_pool_t *pconf,
                             apr_pool_t *ptemp __attribute__((unused)),
                             server_rec *server)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(server->module_config, &gnutls_module);
    if (sc->ocsp == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, APR_EGENERAL, server,
                     "CRITICAL ERROR: %s called with uninitialized OCSP "
                     "data structure. This indicates a bug in mod_gnutls.",
                     __func__);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* set default values for unset parameters */
    if (sc->ocsp_auto_refresh == GNUTLS_ENABLED_UNSET)
        sc->ocsp_auto_refresh = GNUTLS_ENABLED_TRUE;
    if (sc->ocsp_check_nonce == GNUTLS_ENABLED_UNSET)
        sc->ocsp_check_nonce = GNUTLS_ENABLED_TRUE;
    if (sc->ocsp_cache_time == MGS_TIMEOUT_UNSET)
        sc->ocsp_cache_time = apr_time_from_sec(MGS_OCSP_CACHE_TIMEOUT);
    if (sc->ocsp_failure_timeout == MGS_TIMEOUT_UNSET)
        sc->ocsp_failure_timeout = apr_time_from_sec(MGS_OCSP_FAILURE_TIMEOUT);
    if (sc->ocsp_socket_timeout == MGS_TIMEOUT_UNSET)
        sc->ocsp_socket_timeout = apr_time_from_sec(MGS_OCSP_SOCKET_TIMEOUT);
    /* Base fuzz is half the configured maximum, the actual fuzz is
     * between the maximum and half that. The default maximum is
     * sc->ocsp_cache_time / 8, or twice the failure timeout,
     * whichever is larger (so the default guarantees at least one
     * retry before the cache entry expires).*/
    if (sc->ocsp_fuzz_time == MGS_TIMEOUT_UNSET)
    {
        sc->ocsp_fuzz_time = sc->ocsp_cache_time / 16;
        if (sc->ocsp_fuzz_time < sc->ocsp_failure_timeout)
            sc->ocsp_fuzz_time = sc->ocsp_failure_timeout;
    }
    else
        sc->ocsp_fuzz_time = sc->ocsp_fuzz_time / 2;

    /* This really shouldn't happen considering MAX_FUZZ_BASE is about
     * 4.5 years, but better safe than sorry. */
    if (sc->ocsp_fuzz_time > MAX_FUZZ_BASE)
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, APR_EINVAL, server,
                     "%s: Maximum fuzz time is too large, maximum "
                     "supported value is %" APR_INT64_T_FMT " seconds",
                     __func__, apr_time_sec(MAX_FUZZ_BASE) * 2);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    sc->ocsp->fingerprint =
        mgs_get_cert_fingerprint(pconf, sc->certs_x509_crt_chain[0]);
    if (sc->ocsp->fingerprint.data == NULL)
        return HTTP_INTERNAL_SERVER_ERROR;

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

    /* The watchdog structure may be NULL if mod_watchdog is
     * unavailable. */
    if (sc->singleton_wd != NULL
        && sc->ocsp_auto_refresh == GNUTLS_ENABLED_TRUE)
    {
        apr_status_t rv =
            sc->singleton_wd->register_callback(sc->singleton_wd->wd,
                                                sc->ocsp_cache_time,
                                                server, mgs_async_ocsp_update);
        if (rv == APR_SUCCESS)
            ap_log_error(APLOG_MARK, APLOG_INFO, rv, server,
                         "Enabled async OCSP update via watchdog "
                         "for %s:%d",
                         server->server_hostname, server->addrs->host_port);
        else
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, server,
                         "Enabling async OCSP update via watchdog "
                         "for %s:%d failed!",
                         server->server_hostname, server->addrs->host_port);
    }

    return OK;
}

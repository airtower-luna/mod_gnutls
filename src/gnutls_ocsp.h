/*
 *  Copyright 2016-2018 Fiona Klute
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

#ifndef __MOD_GNUTLS_OCSP_H__
#define __MOD_GNUTLS_OCSP_H__

#include "gnutls/gnutls.h"
#include "gnutls/x509.h"
#include "httpd.h"
#include "http_config.h"

#define MGS_OCSP_MUTEX_NAME "gnutls-ocsp"
#define MGS_OCSP_CACHE_MUTEX_NAME "gnutls-ocsp-cache"
#define MGS_OCSP_CACHE_NAME "gnutls_ocsp"

/** Default OCSP response cache timeout in seconds */
#define MGS_OCSP_CACHE_TIMEOUT 3600
/** Default OCSP failure timeout in seconds */
#define MGS_OCSP_FAILURE_TIMEOUT 300
/** Default socket timeout for OCSP responder connections, in
 * seconds. Note that the timeout applies to "absolutely no data sent
 * or received", not the whole connection. 10 seconds in mod_ssl. */
#define MGS_OCSP_SOCKET_TIMEOUT 6

/**
 * Vhost specific OCSP data structure
 */
struct mgs_ocsp_data {
    /** OCSP URI extracted from the server certificate. NULL if
     * unset. */
    apr_uri_t *uri;
    /** Trust list to verify OCSP responses for stapling. Should
     * usually only contain the CA that signed the server
     * certificate. */
    gnutls_x509_trust_list_t *trust;
    /** Server certificate fingerprint, used as cache key for the OCSP
     * response */
    gnutls_datum_t fingerprint;
};

const char *mgs_ocsp_stapling_enable(cmd_parms *parms,
                                     void *dummy __attribute__((unused)),
                                     const int arg);

const char *mgs_set_ocsp_auto_refresh(cmd_parms *parms,
                                      void *dummy __attribute__((unused)),
                                      const int arg);

const char *mgs_set_ocsp_check_nonce(cmd_parms *parms,
                                     void *dummy __attribute__((unused)),
                                     const int arg);

const char *mgs_store_ocsp_response_path(cmd_parms * parms,
                                         void *dummy __attribute__((unused)),
                                         const char *arg);

/**
 * Create a trust list from a certificate chain (one or more
 * certificates).
 *
 * @param tl This trust list will be initialized and filled with the
 * specified certificate(s)
 *
 * @param chain certificate chain, must contain at least `num`
 * certifictes
 *
 * @param num number of certificates to load from chain
 *
 * Chain is supposed to be static (the trust chain of the server
 * certificate), so when `gnutls_x509_trust_list_deinit()` is called on
 * tl later, the "all" parameter should be zero.
 *
 * @return `GNUTLS_E_SUCCESS` or a GnuTLS error code. In case of error
 * tl will be uninitialized.
 */
int mgs_create_ocsp_trust_list(gnutls_x509_trust_list_t *tl,
                               const gnutls_x509_crt_t *chain,
                               const int num);

/**
 * Pool cleanup function that deinits the trust list without
 * deinitializing certificates.
 */
apr_status_t mgs_cleanup_trust_list(void *data);

/**
 * Initialize server config for OCSP, supposed to be called in the
 * post_config hook for each server where OCSP stapling is enabled,
 * after certificates have been loaded.
 *
 * @return OK or DECLINED on success, any other value on error (like
 * the post_config hook itself)
 */
int mgs_ocsp_post_config_server(apr_pool_t *pconf, apr_pool_t *ptemp,
                                server_rec *server);

int mgs_get_ocsp_response(gnutls_session_t session, void *ptr,
                          gnutls_datum_t *ocsp_response);

#endif /* __MOD_GNUTLS_OCSP_H__ */

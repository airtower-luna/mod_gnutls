/*
 *  Copyright 2015-2020 Fiona Klute
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
#include "gnutls_proxy.h"
#include "gnutls_util.h"

#include <apr_strings.h>
#include <gnutls/gnutls.h>

APLOG_USE_MODULE(gnutls);

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
                     "using default '" MGS_DEFAULT_PRIORITY "'.",
                     s->server_hostname, s->addrs->host_port);
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



int mgs_proxy_got_ticket_func(gnutls_session_t session,
                              unsigned int htype,
                              unsigned when,
                              unsigned int incoming __attribute__((unused)),
                              const gnutls_datum_t *msg __attribute__((unused)))
{
    /* Ignore all unexpected messages */
    if (htype != GNUTLS_HANDSHAKE_NEW_SESSION_TICKET
        || when != GNUTLS_HOOK_POST)
        return GNUTLS_E_SUCCESS;

    mgs_handle_t *ctxt = gnutls_session_get_ptr(session);

    /* No cache means we cannot cache tickets. */
    if (!ctxt->sc->cache_enable)
        return GNUTLS_E_SUCCESS;

    if (gnutls_protocol_get_version(ctxt->session) != GNUTLS_TLS1_3)
    {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                      "%s: session tickets for proxy connections are used "
                      "only with TLS 1.3.", __func__);
        return GNUTLS_E_SUCCESS;
    }

    if (!(gnutls_session_get_flags(session) & GNUTLS_SFLAGS_SESSION_TICKET))
    {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, ctxt->c,
                      "%s called but session has no ticket!",
                      __func__);
        /* Tickets are optional, so don't break the session on
         * errors. */
        return GNUTLS_E_SUCCESS;
    }

    gnutls_datum_t ticket;
    int ret = gnutls_session_get_data2(session, &ticket);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                      "%s: error reading session ticket: %s (%d)",
                      __func__, gnutls_strerror(ret), ret);
        if (ticket.data)
            gnutls_free(ticket.data);
        return GNUTLS_E_SUCCESS;
    }

    apr_time_t expiry = apr_time_now() + ctxt->sc->cache_timeout;
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                  "%s: caching session ticket for %s (%u bytes)",
                  __func__, ctxt->proxy_ticket_key.data, ticket.size);
    mgs_cache_store(ctxt->sc->cache, ctxt->c->base_server,
                    ctxt->proxy_ticket_key, ticket, expiry);
    gnutls_free(ticket.data);
    return GNUTLS_E_SUCCESS;
}



/**
 * Returns either a valid hostname for use with SNI, or NULL.
 */
static const char *get_proxy_sni_name(mgs_handle_t *ctxt)
{
    /* Get peer hostname from note left by mod_proxy */
    const char *peer_hostname =
        apr_table_get(ctxt->c->notes, PROXY_SNI_NOTE);

    /* Used only as target for apr_ipsubnet_create() */
    apr_ipsubnet_t *probe;
    /* If the note is present (!= NULL) check that the value is NOT an
     * IP address, which wouldn't be valid for SNI. */
    if ((peer_hostname != NULL)
        && (apr_ipsubnet_create(&probe, peer_hostname, NULL, ctxt->c->pool)
            == APR_SUCCESS))
        return NULL;

    return peer_hostname;
}



static void proxy_conn_set_sni(mgs_handle_t *ctxt)
{
    const char *peer_hostname = get_proxy_sni_name(ctxt);
    if (peer_hostname != NULL)
    {
        int ret = gnutls_server_name_set(ctxt->session, GNUTLS_NAME_DNS,
                                         peer_hostname, strlen(peer_hostname));
        if (ret != GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, ctxt->c,
                          "Could not set SNI '%s' for proxy connection: "
                          "%s (%d)",
                          peer_hostname, gnutls_strerror(ret), ret);
    }
}



/** Initial size for the APR array storing ALPN protocol
 * names. Currently only mod_proxy_http2 uses ALPN for proxy
 * connections and proposes "h2" exclusively. This provides enough
 * room without additional allocation even if an HTTP/1.1 fallback
 * should be added while still being small. */
#define INIT_ALPN_ARR_SIZE 2

/**
 * Set ALPN proposals for a proxy handshake based on the note from the
 * proxy module (see `PROXY_SNI_NOTE`). The note is expected to
 * contain a string, multiple protocol names can be separated by ","
 * or " ", or a combination of them.
 *
 * @param ctxt the mod_gnutls connection handle
 */
static void proxy_conn_set_alpn(mgs_handle_t *ctxt)
{
    const char *proxy_alpn =
        apr_table_get(ctxt->c->notes, PROXY_ALPN_NOTE);
    if (proxy_alpn == NULL)
        return;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, ctxt->c,
                  "%s: proxy module ALPN note is '%s', "
                  "length %" APR_SIZE_T_FMT ".",
                  __func__, proxy_alpn, strlen(proxy_alpn));

    apr_array_header_t* protocols =
        apr_array_make(ctxt->c->pool, INIT_ALPN_ARR_SIZE,
                       sizeof(const char *));

    /* mod_ssl tokenizes the note by "," or " " to allow multiple
     * protocols. We need to copy the note because apr_strtok()
     * modifies the string to make each token NULL terminated. On the
     * plus side that means we do not need to copy individual
     * tokens. */
    char *tok = apr_pstrdup(ctxt->c->pool, proxy_alpn);
    /* state for apr_strtok, pointer to character following current
     * token */
    char *last = NULL;
    while ((tok = apr_strtok(tok, ", ", &last)))
    {
        APR_ARRAY_PUSH(protocols, const char *) = tok;
        tok = NULL;
    }

    gnutls_datum_t* alpn_protos =
        mgs_str_array_to_datum_array(protocols,
                                     ctxt->c->pool,
                                     protocols->nelts);
    int ret = gnutls_alpn_set_protocols(ctxt->session,
                                        alpn_protos,
                                        protocols->nelts,
                                        0 /* flags */);
    if (ret != GNUTLS_E_SUCCESS)
        ap_log_cerror(APLOG_MARK, APLOG_ERR, ret, ctxt->c,
                      "Could not set ALPN proposals for proxy "
                      "connection: %s (%d)",
                      gnutls_strerror(ret), ret);
}



/**
 * Check if there is a cached session for the connection, and load it
 * if yes. The session is deleted from the cache after that, because
 * tickets should not be reused for forward secrecy.
 *
 * @param ctxt the mod_gnutls connection handle
 */
static void proxy_conn_load_session(mgs_handle_t *ctxt)
{
    /* No cache means there cannot be a cached ticket. */
    if (!ctxt->sc->cache_enable)
        return;

    gnutls_datum_t data = {NULL, 0};
    data.data = gnutls_malloc(MGS_SESSION_FETCH_BUF_SIZE);
    if (data.data == NULL)
        return;
    data.size = MGS_SESSION_FETCH_BUF_SIZE;

    apr_status_t rv = mgs_cache_fetch(ctxt->sc->cache, ctxt->c->base_server,
                                      ctxt->proxy_ticket_key, &data,
                                      ctxt->c->pool);
    if (rv != APR_SUCCESS)
    {
        gnutls_free(data.data);
        return;
    }

    /* Best effort attempt to avoid ticket reuse. Unfortunately
     * another thread or process could update (or remove) the cache in
     * between, but that can't be avoided without forcing use of a
     * global mutex even with a multiprocess-safe socache provider. */
    mgs_cache_delete(ctxt->sc->cache, ctxt->c->base_server,
                     ctxt->proxy_ticket_key, ctxt->c->pool);

    int ret = gnutls_session_set_data(ctxt->session, data.data, data.size);
    if (ret == GNUTLS_E_SUCCESS)
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                      "%s: Cached session loaded.", __func__);
    else
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, ctxt->c,
                      "%s: Loading cached session failed: %s (%d)",
                      __func__, gnutls_strerror(ret), ret);
    gnutls_free(data.data);
}



gnutls_datum_t mgs_proxy_ticket_id(mgs_handle_t *ctxt, apr_pool_t *pool)
{
    apr_pool_t *tmp;
    if (pool)
        tmp = pool;
    else
        tmp = ctxt->c->pool;

    /* c->client_addr->port and c->client_ip actually contain
     * information on the remote server for outgoing proxy
     * connections, prefer SNI hostname over IP.
     *
     * The server_hostname is used to tie the cache entry to a
     * specific vhost, because different vhosts may have different
     * settings for the same backend server.
     */
    const char *peer_hostname = get_proxy_sni_name(ctxt);
    gnutls_datum_t key;
    key.data = (unsigned char *)
        apr_psprintf(tmp, "proxy:%s:%s:%d",
                     ctxt->c->base_server->server_hostname,
                     peer_hostname ? peer_hostname : ctxt->c->client_ip,
                     ctxt->c->client_addr->port);
    key.size = strlen((const char*) key.data);
    return key;
}



void mgs_set_proxy_handshake_ext(mgs_handle_t *ctxt)
{
    proxy_conn_set_sni(ctxt);
    proxy_conn_set_alpn(ctxt);
    proxy_conn_load_session(ctxt);
}

/**
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
 *  Copyright 2013-2014 Daniel Kahn Gillmor
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
#include "http_vhost.h"
#include "ap_mpm.h"
#include "mod_status.h"

#ifdef ENABLE_MSVA
#include <msv/msv.h>
#endif

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

#if !USING_2_1_RECENT
extern server_rec *ap_server_conf;
#endif

#if MOD_GNUTLS_DEBUG
static apr_file_t *debug_log_fp;
#endif

static gnutls_datum_t session_ticket_key = {NULL, 0};

static int mgs_cert_verify(request_rec * r, mgs_handle_t * ctxt);
/* use side==0 for server and side==1 for client */
static void mgs_add_common_cert_vars(request_rec * r, gnutls_x509_crt_t cert, int side, size_t export_cert_size);
static void mgs_add_common_pgpcert_vars(request_rec * r, gnutls_openpgp_crt_t cert, int side, size_t export_cert_size);
static int mgs_status_hook(request_rec *r, int flags);
#ifdef ENABLE_MSVA
static const char* mgs_x509_construct_uid(request_rec * pool, gnutls_x509_crt_t cert);
#endif

/* Pool Cleanup Function */
apr_status_t mgs_cleanup_pre_config(void *data __attribute__((unused))) {
	/* Free all session data */
    gnutls_free(session_ticket_key.data);
    session_ticket_key.data = NULL;
    session_ticket_key.size = 0;
	/* Deinitialize GnuTLS Library */
    gnutls_global_deinit();
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

	/* Initialize GnuTLS Library */
    ret = gnutls_global_init();
    if (ret < 0) {
		ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, plog, "gnutls_global_init: %s", gnutls_strerror(ret));
		return DONE;
    }

	/* Generate a Session Key */
    ret = gnutls_session_ticket_key_generate(&session_ticket_key);
    if (ret < 0) {
		ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, plog, "gnutls_session_ticket_key_generate: %s", gnutls_strerror(ret));
		return DONE;
    }

    AP_OPTIONAL_HOOK(status_hook, mgs_status_hook, NULL, NULL, APR_HOOK_MIDDLE);

	/* Register a pool clean-up function */
    apr_pool_cleanup_register(pconf, NULL, mgs_cleanup_pre_config, apr_pool_cleanup_null);

    return OK;
}

static int mgs_select_virtual_server_cb(gnutls_session_t session) {

    mgs_handle_t *ctxt = NULL;
    mgs_srvconf_rec *tsc = NULL;
    int ret = 0;

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);

    ctxt = gnutls_transport_get_ptr(session);

    /* find the virtual server */
    tsc = mgs_find_sni_server(session);

    if (tsc != NULL) {
        // Found a TLS vhost based on the SNI from the client; use it instead.
        ctxt->sc = tsc;
	}

    gnutls_certificate_server_set_request(session, ctxt->sc->client_verify_mode);

    /* Set Anon credentials */
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, ctxt->sc->certs);
	/* Set x509 credentials */
    gnutls_credentials_set(session, GNUTLS_CRD_ANON, ctxt->sc->anon_creds);

#ifdef ENABLE_SRP
	/* Set SRP credentials */
    if (ctxt->sc->srp_tpasswd_conf_file != NULL && ctxt->sc->srp_tpasswd_file != NULL) {
        gnutls_credentials_set(session, GNUTLS_CRD_SRP, ctxt->sc->srp_creds);
    }
#endif

    /* update the priorities - to avoid negotiating a ciphersuite that is not
     * enabled on this virtual server. Note that here we ignore the version
     * negotiation.
     */

    ret = gnutls_priority_set(session, ctxt->sc->priorities);
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
    } else if (gnutls_certificate_type_get(session) == GNUTLS_CRT_OPENPGP) {
		// OPENPGP CERTIFICATE
        *pcerts = ctxt->sc->cert_pgp;
        *pcert_length = 1;
        *privkey = ctxt->sc->privkey_pgp;
        return 0;
    } else {
		// UNKNOWN CERTIFICATE
	    return -1;
	}
}

/* Read the common name or the alternative name of the certificate.
 * We only support a single name per certificate.
 *
 * Returns negative on error.
 */
static int read_crt_cn(server_rec * s, apr_pool_t * p, gnutls_x509_crt_t cert, char **cert_cn) {

    int rv = 0, i;
    size_t data_len;


    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    *cert_cn = NULL;

    data_len = 0;
    rv = gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, NULL, &data_len);

    if (rv == GNUTLS_E_SHORT_MEMORY_BUFFER && data_len > 1) {
        *cert_cn = apr_palloc(p, data_len);
        rv = gnutls_x509_crt_get_dn_by_oid(cert,
                GNUTLS_OID_X520_COMMON_NAME,
                0, 0, *cert_cn,
                &data_len);
    } else { /* No CN return subject alternative name */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "No common name found in certificate for '%s:%d'. Looking for subject alternative name...",
                s->server_hostname, s->port);
        rv = 0;
        /* read subject alternative name */
        for (i = 0; !(rv < 0); i++) {
            data_len = 0;
            rv = gnutls_x509_crt_get_subject_alt_name(cert, i,
                    NULL,
                    &data_len,
                    NULL);

            if (rv == GNUTLS_E_SHORT_MEMORY_BUFFER
                    && data_len > 1) {
                /* FIXME: not very efficient. What if we have several alt names
                 * before DNSName?
                 */
                *cert_cn = apr_palloc(p, data_len + 1);

                rv = gnutls_x509_crt_get_subject_alt_name
                        (cert, i, *cert_cn, &data_len, NULL);
                (*cert_cn)[data_len] = 0;

                if (rv == GNUTLS_SAN_DNSNAME)
                    break;
            }
        }
    }

    return rv;
}

static int read_pgpcrt_cn(server_rec * s, apr_pool_t * p,
        gnutls_openpgp_crt_t cert, char **cert_cn) {
    int rv = 0;
    size_t data_len;


    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    *cert_cn = NULL;

    data_len = 0;
    rv = gnutls_openpgp_crt_get_name(cert, 0, NULL, &data_len);

    if (rv == GNUTLS_E_SHORT_MEMORY_BUFFER && data_len > 1) {
        *cert_cn = apr_palloc(p, data_len);
        rv = gnutls_openpgp_crt_get_name(cert, 0, *cert_cn,
                &data_len);
    } else { /* No CN return subject alternative name */
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                "No name found in PGP certificate for '%s:%d'.",
                s->server_hostname, s->port);
    }

    return rv;
}

int mgs_hook_post_config(apr_pool_t * p, apr_pool_t * plog __attribute__((unused)), apr_pool_t * ptemp __attribute__((unused)), server_rec * base_server) {

    int rv;
    server_rec *s;
    gnutls_dh_params_t dh_params = NULL;
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


    rv = mgs_cache_post_config(p, s, sc_base);
    if (rv != 0) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, s,
                "GnuTLS: Post Config for GnuTLSCache Failed."
                " Shutting Down.");
        exit(-1);
    }

    for (s = base_server; s; s = s->next) {
        sc = (mgs_srvconf_rec *) ap_get_module_config(s->module_config, &gnutls_module);
        sc->cache_type = sc_base->cache_type;
        sc->cache_config = sc_base->cache_config;
        sc->cache_timeout = sc_base->cache_timeout;

        rv = mgs_load_files(p, s);
        if (rv != 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                "GnuTLS: Loading required files failed."
                " Shutting Down.");
            exit(-1);
        }

        /* defaults for unset values: */
        if (sc->enabled == GNUTLS_ENABLED_UNSET)
            sc->enabled = GNUTLS_ENABLED_FALSE;
        if (sc->tickets == GNUTLS_ENABLED_UNSET)
            sc->tickets = GNUTLS_ENABLED_TRUE;
        if (sc->export_certificates_size < 0)
            sc->export_certificates_size = 0;
        if (sc->client_verify_mode ==  -1)
            sc->client_verify_mode = GNUTLS_CERT_IGNORE;
        if (sc->client_verify_method ==  mgs_cvm_unset)
            sc->client_verify_method = mgs_cvm_cartel;

        /* Check if the priorities have been set */
        if (sc->priorities == NULL && sc->enabled == GNUTLS_ENABLED_TRUE) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                    "GnuTLS: Host '%s:%d' is missing the GnuTLSPriorities directive!",
                    s->server_hostname, s->port);
            exit(-1);
        }

        /* Check if DH params have been set per host */
        if (sc->dh_params != NULL) {
            gnutls_certificate_set_dh_params(sc->certs, sc->dh_params);
            gnutls_anon_set_server_dh_params(sc->anon_creds, sc->dh_params);
        } else if (dh_params) {
            gnutls_certificate_set_dh_params(sc->certs, dh_params);
            gnutls_anon_set_server_dh_params(sc->anon_creds, dh_params);
        }

        gnutls_certificate_set_retrieve_function2(sc->certs, cert_retrieve_fn);

        if ((sc->certs_x509_chain == NULL || sc->certs_x509_chain_num < 1) &&
            sc->cert_pgp == NULL && sc->enabled == GNUTLS_ENABLED_TRUE) {
			ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
						"GnuTLS: Host '%s:%d' is missing a Certificate File!",
						s->server_hostname, s->port);
            exit(-1);
        }
        if (sc->enabled == GNUTLS_ENABLED_TRUE &&
            ((sc->certs_x509_chain_num > 0 && sc->privkey_x509 == NULL) ||
             (sc->cert_crt_pgp[0] != NULL && sc->privkey_pgp == NULL))) {
			ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
						"GnuTLS: Host '%s:%d' is missing a Private Key File!",
						s->server_hostname, s->port);
            exit(-1);
        }

        if (sc->enabled == GNUTLS_ENABLED_TRUE) {
            rv = -1;
            if (sc->certs_x509_chain_num > 0) {
                rv = read_crt_cn(s, p, sc->certs_x509_crt_chain[0], &sc->cert_cn);
            }
            if (rv < 0 && sc->cert_pgp != NULL) {
                rv = read_pgpcrt_cn(s, p, sc->cert_crt_pgp[0], &sc->cert_cn);
			}

            if (rv < 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
							"GnuTLS: Cannot find a certificate for host '%s:%d'!",
							s->server_hostname, s->port);
                sc->cert_cn = NULL;
                continue;
            }
        }
    }


    ap_add_version_component(p, "mod_gnutls/" MOD_GNUTLS_VERSION);

    {
        const char* libvers = gnutls_check_version(NULL);
        char* gnutls_version = NULL;
        if(libvers && (gnutls_version = apr_psprintf(p, "GnuTLS/%s", libvers))) {
            ap_add_version_component(p, gnutls_version);
        } else {
            // In case we could not create the above string go for the static version instead
            ap_add_version_component(p, "GnuTLS/" GNUTLS_VERSION "-static");
        }
    }

    return OK;
}

void mgs_hook_child_init(apr_pool_t * p, server_rec *s) {
    apr_status_t rv = APR_SUCCESS;
    mgs_srvconf_rec *sc =
        (mgs_srvconf_rec *) ap_get_module_config(s->module_config, &gnutls_module);

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    /* if we use PKCS #11 reinitialize it */

    if (mgs_pkcs11_reinit(s) < 0) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                    "GnuTLS: Failed to reinitialize PKCS #11");
	    exit(-1);
    }

    if (sc->cache_type != mgs_cache_none) {
        rv = mgs_cache_child_init(p, s, sc);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                    "GnuTLS: Failed to run Cache Init");
        }
    }
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

#define MAX_HOST_LEN 255

#if USING_2_1_RECENT

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
 * @return true if a match, false otherwise
 *
 */
int check_server_aliases(vhost_cb_rec *x, server_rec * s, mgs_srvconf_rec *tsc) {
	apr_array_header_t *names;
	int i,rv = 0;
	char ** name;

	/* Check ServerName First! */
	if(apr_strnatcasecmp(x->sni_name, s->server_hostname) == 0) {
		// We have a match, save this server configuration
		x->sc = tsc;
		rv = 1;
	/* Check any ServerAlias directives */
	} else if(s->names->nelts) {
		names = s->names;
		name = (char **)names->elts;
		for (i = 0; i < names->nelts; ++i) {
			if (!name[i]) { continue; }
				if (apr_strnatcasecmp(x->sni_name, name[i]) == 0) {
					// We have a match, save this server configuration
					x->sc = tsc;
					rv = 1;
			}
		}
	/* Wild any ServerAlias Directives */
	} else if(s->wild_names->nelts) {
		names = s->wild_names;
    	name = (char **)names->elts;
		for (i = 0; i < names->nelts; ++i) {
			if (!name[i]) { continue; }
				if(apr_fnmatch(name[i], x->sni_name ,
								APR_FNM_CASE_BLIND|
								APR_FNM_PERIOD|
								APR_FNM_PATHNAME|
								APR_FNM_NOESCAPE) == APR_SUCCESS) {
				x->sc = tsc;
				rv = 1;
			}
		}
	}
	return rv;
}

static int vhost_cb(void *baton, conn_rec * conn __attribute__((unused)), server_rec * s) {
    mgs_srvconf_rec *tsc;
    vhost_cb_rec *x = baton;
    int ret;

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    tsc = (mgs_srvconf_rec *) ap_get_module_config(s->module_config,
            &gnutls_module);

    if (tsc->enabled != GNUTLS_ENABLED_TRUE || tsc->cert_cn == NULL) {
        return 0;
    }

    if (tsc->certs_x509_chain_num > 0) {
        /* this check is there to warn administrator of any missing hostname
         * in the certificate. */
        ret = gnutls_x509_crt_check_hostname(tsc->certs_x509_crt_chain[0], s->server_hostname);
        if (0 == ret)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "GnuTLS: the certificate doesn't match requested hostname "
                         "'%s'", s->server_hostname);
    } else {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "GnuTLS: SNI request for '%s' but no X.509 certs available at all",
                     s->server_hostname);
    }
	return check_server_aliases(x, s, tsc);
}
#endif

mgs_srvconf_rec *mgs_find_sni_server(gnutls_session_t session) {
    int rv;
    unsigned int sni_type;
    size_t data_len = MAX_HOST_LEN;
    char sni_name[MAX_HOST_LEN];
    mgs_handle_t *ctxt;
#if USING_2_1_RECENT
    vhost_cb_rec cbx;
#else
    server_rec *s;
    mgs_srvconf_rec *tsc;
#endif

    if (session == NULL)
        return NULL;

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    ctxt = gnutls_transport_get_ptr(session);

    rv = gnutls_server_name_get(ctxt->session, sni_name,
            &data_len, &sni_type, 0);

    if (rv != 0) {
        return NULL;
    }

    if (sni_type != GNUTLS_NAME_DNS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0,
                ctxt->c->base_server,
                "GnuTLS: Unknown type '%d' for SNI: "
                "'%s'", sni_type, sni_name);
        return NULL;
    }

    /**
     * Code in the Core already sets up the c->base_server as the base
     * for this IP/Port combo.  Trust that the core did the 'right' thing.
     */
#if USING_2_1_RECENT
    cbx.ctxt = ctxt;
    cbx.sc = NULL;
    cbx.sni_name = sni_name;

    rv = ap_vhost_iterate_given_conn(ctxt->c, vhost_cb, &cbx);
    if (rv == 1) {
        return cbx.sc;
    }
#else
    for (s = ap_server_conf; s; s = s->next) {

        tsc = (mgs_srvconf_rec *) ap_get_module_config(s->module_config,
                &gnutls_module);

        if (tsc->enabled != GNUTLS_ENABLED_TRUE) { continue; }

				if(check_server_aliases(x, s, tsc)) {
					return tsc;
				}
#endif
    return NULL;
}

static void create_gnutls_handle(conn_rec * c)
{
    /* Get mod_gnutls server configuration */
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
            ap_get_module_config(c->base_server->module_config, &gnutls_module);

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);

    /* Get connection specific configuration */
    mgs_handle_t *ctxt = (mgs_handle_t *) ap_get_module_config(c->conn_config, &gnutls_module);
    if (ctxt == NULL)
    {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "%s: allocating connection memory", __func__);
        ctxt = apr_pcalloc(c->pool, sizeof (*ctxt));
        ap_set_module_config(c->conn_config, &gnutls_module, ctxt);
    }
    ctxt->enabled = GNUTLS_ENABLED_TRUE;
    ctxt->c = c;
    ctxt->sc = sc;
    ctxt->status = 0;
    ctxt->input_rc = APR_SUCCESS;
    ctxt->input_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    ctxt->input_cbuf.length = 0;
    ctxt->output_rc = APR_SUCCESS;
    ctxt->output_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    ctxt->output_blen = 0;
    ctxt->output_length = 0;

    /* Initialize GnuTLS Library */
    int err = gnutls_init(&ctxt->session, GNUTLS_SERVER);
    if (err != GNUTLS_E_SUCCESS)
        ap_log_cerror(APLOG_MARK, APLOG_ERR, err, c, "gnutls_init failed!");
    /* Initialize Session Tickets */
    if (session_ticket_key.data != NULL && ctxt->sc->tickets != 0) {
        err = gnutls_session_ticket_enable_server(ctxt->session, &session_ticket_key);
        if (err != GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_ERR, err, c, "gnutls_session_ticket_enable_server failed!");
    }

    /* Set Default Priority */
	err = gnutls_priority_set_direct(ctxt->session, "NORMAL", NULL);
    if (err != GNUTLS_E_SUCCESS)
        ap_log_cerror(APLOG_MARK, APLOG_ERR, err, c, "gnutls_priority_set_direct failed!");
    /* Set Handshake function */
    gnutls_handshake_set_post_client_hello_function(ctxt->session,
            mgs_select_virtual_server_cb);
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

    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(c->base_server->module_config, &gnutls_module);
    mgs_handle_t *ctxt = (mgs_handle_t *)
        ap_get_module_config(c->conn_config, &gnutls_module);

    if ((sc && (!sc->enabled || sc->proxy_enabled == GNUTLS_ENABLED_TRUE))
        || (ctxt && ctxt->enabled == GNUTLS_ENABLED_FALSE))
    {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "%s declined connection",
                      __func__);
        return DECLINED;
    }

    create_gnutls_handle(c);
    return OK;
}

int mgs_hook_fixups(request_rec * r) {
    unsigned char sbuf[GNUTLS_MAX_SESSION_ID];
    char buf[AP_IOBUFSIZE];
    const char *tmp;
    size_t len;
    mgs_handle_t *ctxt;
    int rv = OK;

    if (r == NULL)
        return DECLINED;

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    apr_table_t *env = r->subprocess_env;

    ctxt = ap_get_module_config(r->connection->conn_config,
                                &gnutls_module);

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

    apr_table_setn(env, "SSL_COMPRESS_METHOD",
            gnutls_compression_get_name(gnutls_compression_get(ctxt->session)));

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
    tmp = mgs_session_id2sz(sbuf, len, buf, sizeof (buf));
    apr_table_setn(env, "SSL_SESSION_ID", apr_pstrdup(r->pool, tmp));

    if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_X509) {
	mgs_add_common_cert_vars(r, ctxt->sc->certs_x509_crt_chain[0], 0, ctxt->sc->export_certificates_size);
    } else if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_OPENPGP) {
        mgs_add_common_pgpcert_vars(r, ctxt->sc->cert_crt_pgp[0], 0, ctxt->sc->export_certificates_size);
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
    ctxt =
            ap_get_module_config(r->connection->conn_config,
            &gnutls_module);

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
    int ret, i;

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
    tmp = mgs_session_id2sz(sbuf, len, buf, sizeof (buf));
    apr_table_setn(env, MGS_SIDE("_M_SERIAL"), apr_pstrdup(r->pool, tmp));

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
    for (i = 0; !(ret < 0); i++) {
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


/* @param side 0: server, 1: client
 *
 * @param export_cert_size (int) maximum size for environment variable
 * to use for the PEM-encoded certificate (0 means do not export)
 */
static void mgs_add_common_pgpcert_vars(request_rec * r, gnutls_openpgp_crt_t cert, int side, size_t export_cert_size) {

	unsigned char sbuf[64]; /* buffer to hold serials */
    char buf[AP_IOBUFSIZE];
    const char *tmp;
    size_t len;
    int ret;

    if (r == NULL)
        return;

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);
    apr_table_t *env = r->subprocess_env;

    if (export_cert_size > 0) {
        len = 0;
        ret = gnutls_openpgp_crt_export(cert, GNUTLS_OPENPGP_FMT_BASE64, NULL, &len);
        if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
            if (len >= export_cert_size) {
                apr_table_setn(env, MGS_SIDE("_CERT"),
                               "GNUTLS_CERTIFICATE_SIZE_LIMIT_EXCEEDED");
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "GnuTLS: Failed to export too-large OpenPGP certificate to environment");
            } else {
                char* cert_buf = apr_palloc(r->pool, len + 1);
                if (cert_buf != NULL && gnutls_openpgp_crt_export(cert, GNUTLS_OPENPGP_FMT_BASE64, cert_buf, &len) >= 0) {
                    cert_buf[len] = 0;
                    apr_table_setn(env, MGS_SIDE("_CERT"), cert_buf);
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                                  "GnuTLS: failed to export OpenPGP certificate");
                }
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "GnuTLS: dazed and confused about OpenPGP certificate size");
        }
    }

    len = sizeof (buf);
    gnutls_openpgp_crt_get_name(cert, 0, buf, &len);
    apr_table_setn(env, MGS_SIDE("_NAME"), apr_pstrmemdup(r->pool, buf, len));

    len = sizeof (sbuf);
    gnutls_openpgp_crt_get_fingerprint(cert, sbuf, &len);
    tmp = mgs_session_id2sz(sbuf, len, buf, sizeof (buf));
    apr_table_setn(env, MGS_SIDE("_FINGERPRINT"), apr_pstrdup(r->pool, tmp));

    ret = gnutls_openpgp_crt_get_version(cert);
    if (ret > 0)
        apr_table_setn(env, MGS_SIDE("_M_VERSION"),
                       apr_psprintf(r->pool, "%u", ret));

    apr_table_setn(env, MGS_SIDE("_CERT_TYPE"), "OPENPGP");

    tmp =
            mgs_time2sz(gnutls_openpgp_crt_get_expiration_time
            (cert), buf, sizeof (buf));
    apr_table_setn(env, MGS_SIDE("_V_END"), apr_pstrdup(r->pool, tmp));

    tmp =
            mgs_time2sz(gnutls_openpgp_crt_get_creation_time
            (cert), buf, sizeof (buf));
    apr_table_setn(env, MGS_SIDE("_V_START"), apr_pstrdup(r->pool, tmp));

    ret = gnutls_openpgp_crt_get_pk_algorithm(cert, NULL);
    if (ret >= 0) {
        apr_table_setn(env, MGS_SIDE("_A_KEY"), gnutls_pk_algorithm_get_name(ret));
    }

}

/* TODO: Allow client sending a X.509 certificate chain */
static int mgs_cert_verify(request_rec * r, mgs_handle_t * ctxt) {
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size, status;
    int rv = GNUTLS_E_NO_CERTIFICATE_FOUND, ret;
    unsigned int ch_size = 0;

    union {
        gnutls_x509_crt_t x509[MAX_CHAIN_SIZE];
        gnutls_openpgp_crt_t pgp;
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
    } else if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_OPENPGP) {
        if (cert_list_size > 1) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "GnuTLS: Failed to Verify Peer: "
                    "Chained Client Certificates are not supported.");
            return HTTP_FORBIDDEN;
        }

        gnutls_openpgp_crt_init(&cert.pgp);
        rv = gnutls_openpgp_crt_import(cert.pgp, &cert_list[0],
                GNUTLS_OPENPGP_FMT_RAW);

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
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "GnuTLS: Failed to Verify X.509 Peer: method '%s' is not supported",
                          mgs_readable_cvm(ctxt->sc->client_verify_method));
        }

    } else {
        apr_time_ansi_put(&expiration_time,
                gnutls_openpgp_crt_get_expiration_time
                (cert.pgp));

        switch(ctxt->sc->client_verify_method) {
        case mgs_cvm_cartel:
            rv = gnutls_openpgp_crt_verify_ring(cert.pgp,
                                                ctxt->sc->pgp_list, 0,
                                                &status);
            break;
#ifdef ENABLE_MSVA
        case mgs_cvm_msva:
            /* need to set status and rv */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "GnuTLS:  OpenPGP verification via MSVA is not yet implemented");
            rv = GNUTLS_E_UNIMPLEMENTED_FEATURE;
            break;
#endif
        default:
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "GnuTLS: Failed to Verify OpenPGP Peer: method '%s' is not supported",
                          mgs_readable_cvm(ctxt->sc->client_verify_method));
        }
    }

    if (rv < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "GnuTLS: Failed to Verify Peer certificate: (%d) %s",
                rv, gnutls_strerror(rv));
        if (rv == GNUTLS_E_NO_CERTIFICATE_FOUND)
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r,
                "GnuTLS: No certificate was found for verification. Did you set the GnuTLSX509CAFile or GnuTLSPGPKeyringFile directives?");
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

    if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_X509)
        mgs_add_common_cert_vars(r, cert.x509[0], 1, ctxt->sc->export_certificates_size);
    else if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_OPENPGP)
        mgs_add_common_pgpcert_vars(r, cert.pgp, 1, ctxt->sc->export_certificates_size);

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
    if (gnutls_certificate_type_get(ctxt->session) == GNUTLS_CRT_X509) {
        unsigned int i;
        for (i = 0; i < ch_size; i++) {
            gnutls_x509_crt_deinit(cert.x509[i]);
        }
    } else if (gnutls_certificate_type_get(ctxt->session) ==
            GNUTLS_CRT_OPENPGP)
        gnutls_openpgp_crt_deinit(cert.pgp);
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

 * TODO: we might need another parallel for OpenPGP, but for that it's
 * much simpler: we can just assume that the first User ID marked as
 * "primary" (or the first User ID, period) is the identity the user
 * is trying to present as.

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

static int mgs_status_hook(request_rec *r, int flags __attribute__((unused)))
{
    mgs_srvconf_rec *sc;

    if (r == NULL)
        return OK;

    sc = (mgs_srvconf_rec *) ap_get_module_config(r->server->module_config, &gnutls_module);

    _gnutls_log(debug_log_fp, "%s: %d\n", __func__, __LINE__);

    ap_rputs("<hr>\n", r);
    ap_rputs("<h2>GnuTLS Information:</h2>\n<dl>\n", r);

    ap_rprintf(r, "<dt>GnuTLS version:</dt><dd>%s</dd>\n", gnutls_check_version(NULL));
    ap_rputs("<dt>Built against:</dt><dd>" GNUTLS_VERSION "</dd>\n", r);
    ap_rprintf(r, "<dt>using TLS:</dt><dd>%s</dd>\n", (sc->enabled == GNUTLS_ENABLED_FALSE ? "no" : "yes"));
    if (sc->enabled != GNUTLS_ENABLED_FALSE) {
        mgs_handle_t* ctxt;
        ctxt = ap_get_module_config(r->connection->conn_config, &gnutls_module);
        if (ctxt && ctxt->session != NULL) {
#if GNUTLS_VERSION_MAJOR < 3
            ap_rprintf(r, "<dt>This TLS Session:</dt><dd>%s</dd>\n",
                gnutls_cipher_suite_get_name(gnutls_kx_get(ctxt->session),
                gnutls_cipher_get(ctxt->session),
                gnutls_mac_get(ctxt->session)));
#else
            char* z = NULL;
            z = gnutls_session_get_desc(ctxt->session);
            if (z) {
                ap_rprintf(r, "<dt>This TLS Session:</dt><dd>%s</dd>\n", z);
                gnutls_free(z);
            }
#endif
        }
    }

    ap_rputs("</dl>\n", r);
    return OK;
}


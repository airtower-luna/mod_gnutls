/*
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008, 2014 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
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

#include "gnutls_cache.h"
#include "gnutls_config.h"
#include "mod_gnutls.h"
#include "gnutls_ocsp.h"

#include "apr_lib.h"
#include <apr_strings.h>
#include <gnutls/abstract.h>

#define INIT_CA_SIZE 128

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

static int pin_callback(void *user, int attempt __attribute__((unused)),
                        const char *token_url __attribute__((unused)),
                        const char *token_label, unsigned int flags,
                        char *pin, size_t pin_max)
{
    mgs_srvconf_rec *sc = user;

    if (sc->pin == NULL || flags & GNUTLS_PIN_FINAL_TRY ||
	flags & GNUTLS_PIN_WRONG) {
	return -1;
    }

    if (token_label && strcmp(token_label, "SRK") == 0) {
	 snprintf(pin, pin_max, "%s", sc->srk_pin);
    } else {
         snprintf(pin, pin_max, "%s", sc->pin);
    }
    return 0;
}

static int load_datum_from_file(apr_pool_t * pool,
				const char *file, gnutls_datum_t * data)
{
    apr_file_t *fp;
    apr_finfo_t finfo;
    apr_status_t rv;
    apr_size_t br = 0;

    rv = apr_file_open(&fp, file, APR_READ | APR_BINARY,
		       APR_OS_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
	return rv;
    }

    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, fp);

    if (rv != APR_SUCCESS) {
	return rv;
    }

    data->data = apr_palloc(pool, finfo.size + 1);
    rv = apr_file_read_full(fp, data->data, finfo.size, &br);

    if (rv != APR_SUCCESS) {
	return rv;
    }
    apr_file_close(fp);

    data->data[br] = '\0';
    data->size = br;

    return 0;
}



/**
 * Clean up the various GnuTLS data structures allocated by
 * mgs_load_files()
 */
static apr_status_t mgs_pool_free_credentials(void *arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) arg;

    if (sc->certs)
    {
        gnutls_certificate_free_credentials(sc->certs);
        sc->certs = NULL;
    }

    if (sc->anon_creds)
    {
        gnutls_anon_free_server_credentials(sc->anon_creds);
        sc->anon_creds = NULL;
    }

    if (sc->dh_params)
    {
        gnutls_dh_params_deinit(sc->dh_params);
        sc->dh_params = NULL;
    }

    for (unsigned int i = 0; i < sc->certs_x509_chain_num; i++)
    {
        gnutls_pcert_deinit(&sc->certs_x509_chain[i]);
        gnutls_x509_crt_deinit(sc->certs_x509_crt_chain[i]);
    }

    if (sc->privkey_x509)
    {
        gnutls_privkey_deinit(sc->privkey_x509);
        sc->privkey_x509 = NULL;
    }

    if (sc->ca_list)
    {
        for (unsigned int i = 0; i < sc->ca_list_size; i++)
        {
            gnutls_x509_crt_deinit(sc->ca_list[i]);
        }
        gnutls_free(sc->ca_list);
        sc->ca_list = NULL;
    }

    /* Deinit server priorities only if set from
     * sc->priorities_str. Otherwise the server is using the default
     * global priority cache, which must not be deinitialized here. */
    if (sc->priorities_str && sc->priorities)
    {
        gnutls_priority_deinit(sc->priorities);
        sc->priorities = NULL;
    }

    return APR_SUCCESS;
}

int mgs_load_files(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s)
{
    apr_pool_t *spool;
    const char *file;
    gnutls_datum_t data;
    int ret;
    mgs_srvconf_rec *sc =
        (mgs_srvconf_rec *) ap_get_module_config(s->module_config,
                                                 &gnutls_module);

    apr_pool_create(&spool, ptemp);

    /* Cleanup function for the GnuTLS structures allocated below */
    apr_pool_cleanup_register(pconf, sc, mgs_pool_free_credentials,
                              apr_pool_cleanup_null);

    if (sc->certs == NULL)
    {
        ret = gnutls_certificate_allocate_credentials(&sc->certs);
        if (ret < 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "GnuTLS: Failed to initialize" ": (%d) %s", ret,
                         gnutls_strerror(ret));
            ret = -1;
            goto cleanup;
        }
    }

    if (sc->anon_creds == NULL)
    {
        ret = gnutls_anon_allocate_server_credentials(&sc->anon_creds);
        if (ret < 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "GnuTLS: Failed to initialize" ": (%d) %s", ret,
                         gnutls_strerror(ret));
            ret = -1;
            goto cleanup;
        }
    }

    /* Load user provided DH parameters, if any */
    if (sc->dh_file)
    {
        if (sc->dh_params == NULL)
        {
            ret = gnutls_dh_params_init(&sc->dh_params);
            if (ret < 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Failed to initialize"
                             ": (%d) %s", ret, gnutls_strerror(ret));
                ret = -1;
                goto cleanup;
            }
        }

        if (load_datum_from_file(spool, sc->dh_file, &data) != 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "GnuTLS: Error Reading " "DH params '%s'", sc->dh_file);
            ret = -1;
            goto cleanup;
        }

        ret =
            gnutls_dh_params_import_pkcs3(sc->dh_params, &data,
                                          GNUTLS_X509_FMT_PEM);
        if (ret < 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "GnuTLS: Failed to Import "
                         "DH params '%s': (%d) %s", sc->dh_file, ret,
                         gnutls_strerror(ret));
            ret = -1;
            goto cleanup;
        }
    }

    if (sc->x509_cert_file != NULL && sc->certs_x509_crt_chain == NULL)
    {
        sc->certs_x509_chain =
            apr_pcalloc(pconf,
                        MAX_CHAIN_SIZE * sizeof(sc->certs_x509_chain[0]));
        sc->certs_x509_crt_chain =
            apr_pcalloc(pconf,
                        MAX_CHAIN_SIZE * sizeof(sc->certs_x509_crt_chain[0]));
        unsigned int chain_num = MAX_CHAIN_SIZE;
        unsigned format = GNUTLS_X509_FMT_PEM;

        /* Load X.509 certificate */
        if (strncmp(sc->x509_cert_file, "pkcs11:", 7) == 0) {
            gnutls_pkcs11_obj_t obj;

            file = sc->x509_cert_file;

            ret = gnutls_pkcs11_obj_init(&obj);
            if (ret < 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Error Initializing PKCS #11 object");
                ret = -1;
                goto cleanup;
            }

            gnutls_pkcs11_obj_set_pin_function(obj, pin_callback, sc);

            ret = gnutls_pkcs11_obj_import_url(obj, file,
                                               GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
            if (ret < 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Error Importing PKCS #11 object: "
                             "'%s': %s",
                             file, gnutls_strerror(ret));
                ret = -1;
                goto cleanup;
            }

            format = GNUTLS_X509_FMT_DER;
            ret = gnutls_pkcs11_obj_export2(obj, &data);
            if (ret < 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Error Exporting a PKCS #11 object: "
                             "'%s': %s",
                             file, gnutls_strerror(ret));
                ret = -1;
                goto cleanup;
            }

            gnutls_pkcs11_obj_deinit(obj);
        } else {
            file = ap_server_root_relative(spool, sc->x509_cert_file);

            ret = gnutls_load_file(file, &data);
            if (ret < 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Error Reading Certificate '%s': %s",
                             file, gnutls_strerror(ret));
                ret = -1;
                goto cleanup;
            }
        }

        ret = gnutls_x509_crt_list_import(sc->certs_x509_crt_chain,
                                          &chain_num, &data, format,
                                          GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED);
        gnutls_free(data.data);
        sc->certs_x509_chain_num = chain_num;

        if (ret < 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "GnuTLS: Failed to Import Certificate Chain "
                         "'%s': (%d) %s",
                         file, ret, gnutls_strerror(ret));
            ret = -1;
            goto cleanup;
        }

        for (unsigned int i = 0; i < chain_num; i++)
        {
            ret =
                gnutls_pcert_import_x509(&sc->certs_x509_chain[i],
                                         sc->certs_x509_crt_chain[i], 0);
            if (ret < 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Failed to Import pCertificate "
                             "'%s': (%d) %s",
                             file, ret, gnutls_strerror(ret));
                ret = -1;
                goto cleanup;
            }
        }
        sc->certs_x509_chain_num = chain_num;
    }

    if (sc->x509_key_file && sc->privkey_x509 == NULL)
    {
        ret = gnutls_privkey_init(&sc->privkey_x509);
        if (ret < 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "GnuTLS: Failed to initialize: (%d) %s", ret,
                         gnutls_strerror(ret));
            ret = -1;
            goto cleanup;
        }

        if (gnutls_url_is_supported(sc->x509_key_file) != 0) {
            file = sc->x509_key_file;

            gnutls_privkey_set_pin_function(sc->privkey_x509, pin_callback,
                                            sc);

            ret = gnutls_privkey_import_url(sc->privkey_x509, file, 0);

            if (ret < 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Failed to Import Private Key URL "
                             "'%s': (%d) %s",
                             file, ret, gnutls_strerror(ret));
                ret = -1;
                goto cleanup;
            }
        } else {
            file = ap_server_root_relative(spool, sc->x509_key_file);

            if (load_datum_from_file(spool, file, &data) != 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Error Reading Private Key '%s'",
                             file);
                ret = -1;
                goto cleanup;
            }

            ret =
                gnutls_privkey_import_x509_raw(sc->privkey_x509, &data,
                                               GNUTLS_X509_FMT_PEM, sc->pin,
                                               0);

            if (ret < 0) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Failed to Import Private Key "
                             "'%s': (%d) %s",
                             file, ret, gnutls_strerror(ret));
                ret = -1;
                goto cleanup;
            }
        }
    }

    /* Load the X.509 CA file */
    if (sc->x509_ca_file)
    {
        if (load_datum_from_file(spool, sc->x509_ca_file, &data) != 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "GnuTLS: Error Reading " "Client CA File '%s'",
                         sc->x509_ca_file);
            ret = -1;
            goto cleanup;
        }

        ret = gnutls_x509_crt_list_import2(&sc->ca_list, &sc->ca_list_size,
                                           &data, GNUTLS_X509_FMT_PEM, 0);
        if (ret < 0) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                         "GnuTLS: Failed to load "
                         "Client CA File '%s': (%d) %s", sc->x509_ca_file,
                         ret, gnutls_strerror(ret));
            ret = -1;
            goto cleanup;
        }
    }

    if (sc->priorities_str && sc->priorities == NULL)
    {
        const char *err;
        ret = gnutls_priority_init(&sc->priorities, sc->priorities_str, &err);

        if (ret < 0) {
            if (ret == GNUTLS_E_INVALID_REQUEST) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: Syntax error parsing priorities string at: %s",
                             err);
            } else {
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s,
                             "GnuTLS: error parsing priorities string");

            }
            ret = -1;
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    apr_pool_destroy(spool);

    return ret;
}

int mgs_pkcs11_reinit(server_rec * base_server)
{
    int ret;
    server_rec *s;
    mgs_srvconf_rec *sc;

    gnutls_pkcs11_reinit();

    for (s = base_server; s; s = s->next) {
        sc = (mgs_srvconf_rec *) ap_get_module_config(s->module_config, &gnutls_module);

	    /* gnutls caches the session in a private key, so we need to open
	     * a new one */
	    if (sc->x509_key_file && gnutls_url_is_supported(sc->x509_key_file) != 0) {
	        gnutls_privkey_deinit(sc->privkey_x509);

		ret = gnutls_privkey_init(&sc->privkey_x509);
		if (ret < 0) {
		    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
				 "GnuTLS: Failed to initialize: (%d) %s", ret,
				 gnutls_strerror(ret));
		    goto fail;
		}

		gnutls_privkey_set_pin_function(sc->privkey_x509, pin_callback, sc);

	        ret = gnutls_privkey_import_url(sc->privkey_x509, sc->x509_key_file, 0);
		if (ret < 0) {
		    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
			     "GnuTLS: Failed to Re-Import Private Key URL '%s': (%d) %s",
			     sc->x509_key_file, ret, gnutls_strerror(ret));
		    goto fail;
		}
	    }
    }

    return 0;

 fail:
    gnutls_privkey_deinit(sc->privkey_x509);
    return -1;
}

const char *mgs_set_dh_file(cmd_parms * parms, void *dummy __attribute__((unused)),
        const char *arg) {
    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->server->
						 module_config,
						 &gnutls_module);

    sc->dh_file = ap_server_root_relative(parms->pool, arg);

    return NULL;
}

const char *mgs_set_cert_file(cmd_parms * parms, void *dummy __attribute__((unused)), const char *arg) {

    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->
						 server->module_config,
						 &gnutls_module);

    sc->x509_cert_file = apr_pstrdup(parms->pool, arg);

    return NULL;

}

const char *mgs_set_key_file(cmd_parms * parms, void *dummy __attribute__((unused)), const char *arg) {

    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->
						 server->module_config,
						 &gnutls_module);

    sc->x509_key_file = apr_pstrdup(parms->pool, arg);

    return NULL;
}

const char *mgs_set_tickets(cmd_parms *parms,
                            void *dummy __attribute__((unused)),
                            const int arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    if (arg)
        sc->tickets = GNUTLS_ENABLED_TRUE;
    else
        sc->tickets = GNUTLS_ENABLED_FALSE;

    return NULL;
}

const char *mgs_set_cache(cmd_parms * parms,
                          void *dummy __attribute__((unused)),
                          const char *type, const char *arg)
{
    const char *err;
    mgs_srvconf_rec *sc =
        ap_get_module_config(parms->server->module_config,
                             &gnutls_module);
    if ((err = ap_check_cmd_context(parms, GLOBAL_ONLY)))
        return err;

    unsigned char enable = GNUTLS_ENABLED_TRUE;
    /* none: disable cache */
    if (strcasecmp("none", type) == 0)
        enable = GNUTLS_ENABLED_FALSE;

    /* Try to split socache "type:config" style configuration */
    const char* sep = ap_strchr_c(type, ':');
    if (sep)
    {
        type = apr_pstrmemdup(parms->temp_pool, type, sep - type);
        if (arg != NULL)
        {
            /* No mixing of socache style and legacy config! */
            return "GnuTLSCache appears to have a mod_socache style "
                "type:config value, but there is a second parameter!";
        }
        arg = ++sep;
    }

    mgs_cache_t *cache = NULL;
    /* parms->directive->directive contains the directive string */
    if (!strcasecmp(parms->directive->directive, "GnuTLSCache"))
    {
        if (enable == GNUTLS_ENABLED_FALSE)
        {
            sc->cache_enable = GNUTLS_ENABLED_FALSE;
            return NULL;
        }
        sc->cache_enable = GNUTLS_ENABLED_TRUE;
        cache = &sc->cache;
    }
    else if (!strcasecmp(parms->directive->directive, "GnuTLSOCSPCache"))
    {
        if (enable == GNUTLS_ENABLED_FALSE)
            return "\"GnuTLSOCSPCache none\" is invalid, use "
                "\"GnuTLSOCSPStapling off\" if you want to disable "
                "OCSP stapling.";
        cache = &sc->ocsp_cache;
    }
    else
        return apr_psprintf(parms->temp_pool, "Internal Error: %s "
                            "called for unknown directive %s",
                            __func__, parms->directive->directive);

    return mgs_cache_inst_config(cache, parms->server,
                                 type, arg,
                                 parms->pool, parms->temp_pool);
}

const char *mgs_set_timeout(cmd_parms * parms,
                            void *dummy __attribute__((unused)),
                            const char *arg)
{
    apr_int64_t argint = apr_atoi64(arg);
    /* timeouts cannot be negative */
    if (argint < 0)
        return apr_psprintf(parms->pool, "%s: Invalid argument",
                            parms->directive->directive);

    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    if (!strcasecmp(parms->directive->directive, "GnuTLSCacheTimeout"))
        sc->cache_timeout = apr_time_from_sec(argint);
    else if (!strcasecmp(parms->directive->directive,
                         "GnuTLSOCSPCacheTimeout"))
        sc->ocsp_cache_time = apr_time_from_sec(argint);
    else if (!strcasecmp(parms->directive->directive,
                         "GnuTLSOCSPFailureTimeout"))
        sc->ocsp_failure_timeout = apr_time_from_sec(argint);
    else if (!strcasecmp(parms->directive->directive,
                         "GnuTLSOCSPFuzzTime"))
        sc->ocsp_fuzz_time = apr_time_from_sec(argint);
    else if (!strcasecmp(parms->directive->directive,
                         "GnuTLSOCSPSocketTimeout"))
        sc->ocsp_socket_timeout = apr_time_from_sec(argint);
    else
        /* Can't happen unless there's a serious bug in mod_gnutls or Apache */
        return apr_psprintf(parms->pool,
                            "mod_gnutls: %s called for invalid option '%s'",
                            __func__, parms->directive->directive);

    return NULL;
}

const char *mgs_set_client_verify(cmd_parms * parms,
                                  void *dirconf,
                                  const char *arg) {
    int mode;

    if (strcasecmp("none", arg) == 0 || strcasecmp("ignore", arg) == 0) {
	mode = GNUTLS_CERT_IGNORE;
    } else if (strcasecmp("optional", arg) == 0
	       || strcasecmp("request", arg) == 0) {
	mode = GNUTLS_CERT_REQUEST;
    } else if (strcasecmp("require", arg) == 0) {
	mode = GNUTLS_CERT_REQUIRE;
    } else {
	return "GnuTLSClientVerify: Invalid argument";
    }

    /* This was set from a directory context */
    if (parms->path) {
        mgs_dirconf_rec *dc = (mgs_dirconf_rec *) dirconf;
        dc->client_verify_mode = mode;
    } else {
	mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
	    ap_get_module_config(parms->server->module_config,
				 &gnutls_module);
	sc->client_verify_mode = mode;
    }

    return NULL;
}

const char *mgs_set_client_ca_file(cmd_parms * parms, void *dummy __attribute__((unused)),
        const char *arg) {
    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->server->
						 module_config,
						 &gnutls_module);

    sc->x509_ca_file = ap_server_root_relative(parms->pool, arg);

    return NULL;
}

/*
 * Enable TLS proxy operation if arg is true, disable it otherwise.
 */
const char *mgs_set_proxy_engine(cmd_parms *parms,
                                 void *dummy __attribute__((unused)),
                                 const int arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    if (arg)
        sc->proxy_enabled = GNUTLS_ENABLED_TRUE;
    else
        sc->proxy_enabled = GNUTLS_ENABLED_FALSE;

    return NULL;
}

/*
 * Enable TLS for the server/vhost if arg is true, disable it
 * otherwise.
 */
const char *mgs_set_enabled(cmd_parms *parms,
                            void *dummy __attribute__((unused)),
                            const int arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    if (arg)
        sc->enabled = GNUTLS_ENABLED_TRUE;
    else
        sc->enabled = GNUTLS_ENABLED_FALSE;

    return NULL;
}

const char *mgs_set_export_certificates_size(cmd_parms * parms, void *dummy __attribute__((unused)), const char *arg) {
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) ap_get_module_config(parms->server->module_config, &gnutls_module);
    if (!strcasecmp(arg, "On")) {
	sc->export_certificates_size = 16 * 1024;
    } else if (!strcasecmp(arg, "Off")) {
	sc->export_certificates_size = 0;
    } else {
	char *endptr;
	sc->export_certificates_size = strtol(arg, &endptr, 10);
	while (apr_isspace(*endptr))
	    endptr++;
	if (*endptr == '\0' || *endptr == 'b' || *endptr == 'B') {
	    ;
	} else if (*endptr == 'k' || *endptr == 'K') {
	    sc->export_certificates_size *= 1024;
	} else {
	    return
		"GnuTLSExportCertificates must be set to a size (in bytes) or 'On' or 'Off'";
	}
    }

    return NULL;
}



/*
 * Store GnuTLS priority strings. Used for GnuTLSPriorities and
 * GnuTLSProxyPriorities.
 */
const char *mgs_set_priorities(cmd_parms * parms,
                               void *dummy __attribute__((unused)),
                               const char *arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    if (!strcasecmp(parms->directive->directive, "GnuTLSPriorities"))
        sc->priorities_str = apr_pstrdup(parms->pool, arg);
    else if (!strcasecmp(parms->directive->directive, "GnuTLSProxyPriorities"))
        sc->proxy_priorities_str = apr_pstrdup(parms->pool, arg);
    else
        /* Can't happen unless there's a serious bug in mod_gnutls or Apache */
        return apr_psprintf(parms->pool,
                            "mod_gnutls: %s called for invalid option '%s'",
                            __func__, parms->directive->directive);

    return NULL;
}



const char *mgs_set_pin(cmd_parms * parms, void *dummy __attribute__((unused)),
                        const char *arg)
{

    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
	ap_get_module_config(parms->server->module_config, &gnutls_module);

    sc->pin = apr_pstrdup(parms->pool, arg);

    return NULL;
}

const char *mgs_set_srk_pin(cmd_parms * parms,
                            void *dummy __attribute__((unused)),
                            const char *arg)
{

    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
	ap_get_module_config(parms->server->module_config, &gnutls_module);

    sc->srk_pin = apr_pstrdup(parms->pool, arg);

    return NULL;
}



static mgs_srvconf_rec *_mgs_config_server_create(apr_pool_t * p,
						  char **err __attribute__((unused)))
{
    mgs_srvconf_rec *sc = apr_pcalloc(p, sizeof(*sc));

    sc->enabled = GNUTLS_ENABLED_UNSET;

    sc->privkey_x509 = NULL;
    sc->anon_creds = NULL;
    sc->certs = NULL;
    sc->certs_x509_chain = NULL;
    sc->certs_x509_crt_chain = NULL;
    sc->certs_x509_chain_num = 0;
    sc->p11_modules = NULL;
    sc->pin = NULL;

    sc->priorities_str = NULL;
    sc->cache_timeout = MGS_TIMEOUT_UNSET;
    sc->cache_enable = GNUTLS_ENABLED_UNSET;
    sc->cache = NULL;
    sc->tickets = GNUTLS_ENABLED_UNSET;
    sc->priorities = NULL;
    sc->dh_params = NULL;
    sc->dh_file = NULL;
    sc->ca_list = NULL;
    sc->ca_list_size = 0;
    sc->proxy_enabled = GNUTLS_ENABLED_UNSET;
    sc->export_certificates_size = -1;

    sc->proxy_x509_key_file = NULL;
    sc->proxy_x509_cert_file = NULL;
    sc->proxy_x509_ca_file = NULL;
    sc->proxy_x509_crl_file = NULL;
    sc->proxy_priorities_str = NULL;
    sc->proxy_x509_creds = NULL;
    sc->anon_client_creds = NULL;
    sc->proxy_priorities = NULL;
    sc->proxy_x509_tl = NULL;

    sc->ocsp_staple = GNUTLS_ENABLED_UNSET;
    sc->ocsp_auto_refresh = GNUTLS_ENABLED_UNSET;
    sc->ocsp_check_nonce = GNUTLS_ENABLED_UNSET;
    sc->ocsp_response_file = NULL;
    sc->ocsp_response_file_num = 0;
    sc->ocsp = NULL;
    sc->ocsp_num = 0;
    sc->ocsp_mutex = NULL;
    sc->ocsp_cache = NULL;
    sc->ocsp_cache_time = MGS_TIMEOUT_UNSET;
    sc->ocsp_failure_timeout = MGS_TIMEOUT_UNSET;
    sc->ocsp_fuzz_time = MGS_TIMEOUT_UNSET;
    sc->ocsp_socket_timeout = MGS_TIMEOUT_UNSET;

    sc->singleton_wd = NULL;

/* this relies on GnuTLS never changing the gnutls_certificate_request_t enum to define -1 */
    sc->client_verify_mode = -1;

    return sc;
}

void *mgs_config_server_create(apr_pool_t * p,
                               server_rec * s __attribute__((unused))) {
    char *err = NULL;
    mgs_srvconf_rec *sc = _mgs_config_server_create(p, &err);
    if (sc)
	return sc;
    else
	return err;
}

#define gnutls_srvconf_merge(t, unset) sc->t = (add->t == unset) ? base->t : add->t
#define gnutls_srvconf_assign(t) sc->t = add->t

void *mgs_config_server_merge(apr_pool_t * p, void *BASE, void *ADD)
{
    char *err = NULL;
    mgs_srvconf_rec *base = (mgs_srvconf_rec *) BASE;
    mgs_srvconf_rec *add = (mgs_srvconf_rec *) ADD;
    mgs_srvconf_rec *sc = _mgs_config_server_create(p, &err);
    if (NULL == sc)
	return err;

    gnutls_srvconf_merge(enabled, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_merge(tickets, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_merge(proxy_enabled, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_merge(export_certificates_size, -1);
    gnutls_srvconf_merge(client_verify_mode, -1);
    gnutls_srvconf_merge(x509_cert_file, NULL);

    gnutls_srvconf_merge(x509_key_file, NULL);
    gnutls_srvconf_merge(x509_ca_file, NULL);
    gnutls_srvconf_merge(p11_modules, NULL);
    gnutls_srvconf_merge(pin, NULL);
    gnutls_srvconf_merge(dh_file, NULL);
    gnutls_srvconf_merge(priorities_str, NULL);
    gnutls_srvconf_merge(cache_timeout, MGS_TIMEOUT_UNSET);

    gnutls_srvconf_merge(proxy_x509_key_file, NULL);
    gnutls_srvconf_merge(proxy_x509_cert_file, NULL);
    gnutls_srvconf_merge(proxy_x509_ca_file, NULL);
    gnutls_srvconf_merge(proxy_x509_crl_file, NULL);
    gnutls_srvconf_merge(proxy_priorities_str, NULL);
    gnutls_srvconf_merge(proxy_priorities, NULL);

    gnutls_srvconf_merge(ocsp_staple, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_merge(ocsp_auto_refresh, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_merge(ocsp_check_nonce, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_assign(ocsp_response_file);
    gnutls_srvconf_assign(ocsp_response_file_num);
    gnutls_srvconf_merge(ocsp_cache_time, MGS_TIMEOUT_UNSET);
    gnutls_srvconf_merge(ocsp_failure_timeout, MGS_TIMEOUT_UNSET);
    gnutls_srvconf_merge(ocsp_fuzz_time, MGS_TIMEOUT_UNSET);
    gnutls_srvconf_merge(ocsp_socket_timeout, MGS_TIMEOUT_UNSET);

    gnutls_srvconf_assign(ca_list);
    gnutls_srvconf_assign(ca_list_size);
    gnutls_srvconf_assign(certs);
    gnutls_srvconf_assign(anon_creds);
    gnutls_srvconf_assign(certs_x509_chain);
    gnutls_srvconf_assign(certs_x509_crt_chain);
    gnutls_srvconf_assign(certs_x509_chain_num);

    return sc;
}

#undef gnutls_srvconf_merge
#undef gnutls_srvconf_assign

void *mgs_config_dir_merge(apr_pool_t * p,
                           void *basev __attribute__((unused)),
                           void *addv __attribute__((unused))) {
    mgs_dirconf_rec *new;
    /*    mgs_dirconf_rec *base = (mgs_dirconf_rec *) basev; */
    mgs_dirconf_rec *add = (mgs_dirconf_rec *) addv;

    new = (mgs_dirconf_rec *) apr_pcalloc(p, sizeof(mgs_dirconf_rec));
    new->client_verify_mode = add->client_verify_mode;
    return new;
}

void *mgs_config_dir_create(apr_pool_t * p,
                            char *dir __attribute__((unused))) {
    mgs_dirconf_rec *dc = apr_palloc(p, sizeof (*dc));
    dc->client_verify_mode = -1;
    return dc;
}



/*
 * Store paths to proxy credentials
 *
 * This function copies the paths provided in the configuration file
 * into the server configuration. The post configuration hook takes
 * care of actually loading the credentials, which means than invalid
 * paths or the like will be detected there.
 */
const char *mgs_store_cred_path(cmd_parms * parms,
                                void *dummy __attribute__((unused)),
                                const char *arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    /* parms->directive->directive contains the directive string */
    if (!strcasecmp(parms->directive->directive, "GnuTLSProxyKeyFile"))
        sc->proxy_x509_key_file = apr_pstrdup(parms->pool, arg);
    else if (!strcasecmp(parms->directive->directive,
                         "GnuTLSProxyCertificateFile"))
        sc->proxy_x509_cert_file = apr_pstrdup(parms->pool, arg);
    else if (!strcasecmp(parms->directive->directive, "GnuTLSProxyCAFile"))
        sc->proxy_x509_ca_file = apr_pstrdup(parms->pool, arg);
    else if (!strcasecmp(parms->directive->directive, "GnuTLSProxyCRLFile"))
        sc->proxy_x509_crl_file = apr_pstrdup(parms->pool, arg);
    return NULL;
}



/*
 * Record PKCS #11 module to load. Note that the value is only used in
 * the base config, settings in virtual hosts are ignored.
 */
const char *mgs_set_p11_module(cmd_parms * parms,
                               void *dummy __attribute__((unused)),
                               const char *arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);
    /* initialize PKCS #11 module list if necessary */
    if (sc->p11_modules == NULL)
        sc->p11_modules = apr_array_make(parms->pool, 2, sizeof(char*));

    *(char **) apr_array_push(sc->p11_modules) = apr_pstrdup(parms->pool, arg);

    return NULL;
}

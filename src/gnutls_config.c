/**
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
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

static int load_datum_from_file(apr_pool_t * pool,
        const char *file, gnutls_datum_t * data) {
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

const char *mgs_set_dh_file(cmd_parms * parms, void *dummy,
        const char *arg) {
    int ret;
    gnutls_datum_t data;
    const char *file;
    apr_pool_t *spool;
    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);

    apr_pool_create(&spool, parms->pool);

    file = ap_server_root_relative(spool, arg);

    if (load_datum_from_file(spool, file, &data) != 0) {
        return apr_psprintf(parms->pool, "GnuTLS: Error Reading "
                "DH params '%s'", file);
    }

    ret = gnutls_dh_params_init(&sc->dh_params);
    if (ret < 0) {
        return apr_psprintf(parms->pool,
                "GnuTLS: Failed to initialize"
                ": (%d) %s", ret,
                gnutls_strerror(ret));
    }

    ret =
            gnutls_dh_params_import_pkcs3(sc->dh_params, &data,
            GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        return apr_psprintf(parms->pool,
                "GnuTLS: Failed to Import "
                "DH params '%s': (%d) %s", file, ret,
                gnutls_strerror(ret));
    }

    apr_pool_destroy(spool);

    return NULL;
}

const char *mgs_set_cert_file(cmd_parms * parms, void *dummy, const char *arg) {

    int ret;
    gnutls_datum_t data;
    const char *file;
    apr_pool_t *spool;

    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) ap_get_module_config(parms->server->module_config, &gnutls_module);
    apr_pool_create(&spool, parms->pool);

    file = ap_server_root_relative(spool, arg);

    if (load_datum_from_file(spool, file, &data) != 0) {
		apr_pool_destroy(spool);
        return apr_psprintf(parms->pool, "GnuTLS: Error Reading Certificate '%s'", file);
    }

    sc->certs_x509_chain_num = MAX_CHAIN_SIZE;
    ret = gnutls_x509_crt_list_import(sc->certs_x509_chain, &sc->certs_x509_chain_num, &data, GNUTLS_X509_FMT_PEM, 0);
    if (ret < 0) {
		apr_pool_destroy(spool);
        return apr_psprintf(parms->pool, "GnuTLS: Failed to Import Certificate '%s': (%d) %s", file, ret, gnutls_strerror(ret));
    }
    
	apr_pool_destroy(spool);
    return NULL;

}

const char *mgs_set_key_file(cmd_parms * parms, void *dummy, const char *arg) {

    int ret;
    gnutls_datum_t data;
    const char *file;
    apr_pool_t *spool;
    const char *out;

	mgs_srvconf_rec *sc = (mgs_srvconf_rec *) ap_get_module_config(parms->server->module_config, &gnutls_module);
    
	apr_pool_create(&spool, parms->pool);

    file = ap_server_root_relative(spool, arg);

    if (load_datum_from_file(spool, file, &data) != 0) {
        out = apr_psprintf(parms->pool, "GnuTLS: Error Reading Private Key '%s'", file);
		apr_pool_destroy(spool);
        return out;
    }

    ret = gnutls_x509_privkey_init(&sc->privkey_x509);

    if (ret < 0) {
		apr_pool_destroy(spool);
        return apr_psprintf(parms->pool, "GnuTLS: Failed to initialize: (%d) %s", ret, gnutls_strerror(ret));
    }

    ret = gnutls_x509_privkey_import(sc->privkey_x509, &data, GNUTLS_X509_FMT_PEM);

    if (ret < 0) {
        ret = gnutls_x509_privkey_import_pkcs8(sc->privkey_x509, &data, GNUTLS_X509_FMT_PEM, NULL, GNUTLS_PKCS_PLAIN);
	}

    if (ret < 0) {
        out = apr_psprintf(parms->pool, "GnuTLS: Failed to Import Private Key '%s': (%d) %s", file, ret, gnutls_strerror(ret));
		apr_pool_destroy(spool);
        return out;
    }

    apr_pool_destroy(spool);

    return NULL;
}

const char *mgs_set_pgpcert_file(cmd_parms * parms, void *dummy,
        const char *arg) {
    int ret;
    gnutls_datum_t data;
    const char *file;
    apr_pool_t *spool;
    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);
    apr_pool_create(&spool, parms->pool);

    file = ap_server_root_relative(spool, arg);

    if (load_datum_from_file(spool, file, &data) != 0) {
        return apr_psprintf(parms->pool, "GnuTLS: Error Reading "
                "Certificate '%s'", file);
    }

    ret = gnutls_openpgp_crt_init(&sc->cert_pgp);
    if (ret < 0) {
        return apr_psprintf(parms->pool, "GnuTLS: Failed to Init "
                "PGP Certificate: (%d) %s", ret,
                gnutls_strerror(ret));
    }

    ret =
            gnutls_openpgp_crt_import(sc->cert_pgp, &data,
            GNUTLS_OPENPGP_FMT_BASE64);
    if (ret < 0) {
        return apr_psprintf(parms->pool,
                "GnuTLS: Failed to Import "
                "PGP Certificate '%s': (%d) %s", file,
                ret, gnutls_strerror(ret));
    }

    apr_pool_destroy(spool);
    return NULL;
}

const char *mgs_set_pgpkey_file(cmd_parms * parms, void *dummy,
        const char *arg) {
    int ret;
    gnutls_datum_t data;
    const char *file;
    apr_pool_t *spool;
    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);
    apr_pool_create(&spool, parms->pool);

    file = ap_server_root_relative(spool, arg);

    if (load_datum_from_file(spool, file, &data) != 0) {
        return apr_psprintf(parms->pool, "GnuTLS: Error Reading "
                "Private Key '%s'", file);
    }

    ret = gnutls_openpgp_privkey_init(&sc->privkey_pgp);
    if (ret < 0) {
        return apr_psprintf(parms->pool,
                "GnuTLS: Failed to initialize"
                ": (%d) %s", ret,
                gnutls_strerror(ret));
    }

    ret =
            gnutls_openpgp_privkey_import(sc->privkey_pgp, &data,
            GNUTLS_OPENPGP_FMT_BASE64, NULL,
            0);
    if (ret != 0) {
        return apr_psprintf(parms->pool,
                "GnuTLS: Failed to Import "
                "PGP Private Key '%s': (%d) %s", file,
                ret, gnutls_strerror(ret));
    }
    apr_pool_destroy(spool);
    return NULL;
}

const char *mgs_set_tickets(cmd_parms * parms, void *dummy,
        const char *arg) {
    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);

    sc->tickets = 0;
    if (strcasecmp("on", arg) == 0) {
        sc->tickets = 1;
    }

    return NULL;
}


#ifdef ENABLE_SRP

const char *mgs_set_srp_tpasswd_file(cmd_parms * parms, void *dummy,
        const char *arg) {
    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);

    sc->srp_tpasswd_file = ap_server_root_relative(parms->pool, arg);

    return NULL;
}

const char *mgs_set_srp_tpasswd_conf_file(cmd_parms * parms, void *dummy,
        const char *arg) {
    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);

    sc->srp_tpasswd_conf_file =
            ap_server_root_relative(parms->pool, arg);

    return NULL;
}

#endif

const char *mgs_set_cache(cmd_parms * parms, void *dummy,
        const char *type, const char *arg) {
    const char *err;
    mgs_srvconf_rec *sc =
            ap_get_module_config(parms->server->module_config,
            &gnutls_module);
    if ((err = ap_check_cmd_context(parms, GLOBAL_ONLY))) {
        return err;
    }

    if (strcasecmp("none", type) == 0) {
        sc->cache_type = mgs_cache_none;
        sc->cache_config = NULL;
        return NULL;
    } else if (strcasecmp("dbm", type) == 0) {
        sc->cache_type = mgs_cache_dbm;
    } else if (strcasecmp("gdbm", type) == 0) {
        sc->cache_type = mgs_cache_gdbm;
    }
#if HAVE_APR_MEMCACHE
    else if (strcasecmp("memcache", type) == 0) {
        sc->cache_type = mgs_cache_memcache;
    }
#endif
    else {
        return "Invalid Type for GnuTLSCache!";
    }

    if (arg == NULL)
        return "Invalid argument 2 for GnuTLSCache!";

    if (sc->cache_type == mgs_cache_dbm
            || sc->cache_type == mgs_cache_gdbm) {
        sc->cache_config =
                ap_server_root_relative(parms->pool, arg);
    } else {
        sc->cache_config = apr_pstrdup(parms->pool, arg);
    }

    return NULL;
}

const char *mgs_set_cache_timeout(cmd_parms * parms, void *dummy,
        const char *arg) {
    int argint;
    const char *err;
    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);

    if ((err = ap_check_cmd_context(parms, GLOBAL_ONLY))) {
        return err;
    }

    argint = atoi(arg);

    if (argint < 0) {
        return "GnuTLSCacheTimeout: Invalid argument";
    } else if (argint == 0) {
        sc->cache_timeout = 0;
    } else {
        sc->cache_timeout = apr_time_from_sec(argint);
    }

    return NULL;
}

const char *mgs_set_client_verify_method(cmd_parms * parms, void *dummy,
        const char *arg) {
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)ap_get_module_config(parms->server->module_config, &gnutls_module);

    if (strcasecmp("cartel", arg) == 0) {
        sc->client_verify_method = mgs_cvm_cartel;
    } else if (strcasecmp("msva", arg) == 0) {
#ifdef ENABLE_MSVA
        sc->client_verify_method = mgs_cvm_msva;
#else
        return "GnuTLSClientVerifyMethod: msva is not supported";
#endif
    } else {
        return "GnuTLSClientVerifyMethod: Invalid argument";
    }

    return NULL;
}

const char *mgs_set_client_verify(cmd_parms * parms, void *dummy,
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
        mgs_dirconf_rec *dc = (mgs_dirconf_rec *) dummy;
        dc->client_verify_mode = mode;
    } else {
        mgs_srvconf_rec *sc =
                (mgs_srvconf_rec *)
                ap_get_module_config(parms->server->module_config,
                &gnutls_module);
        sc->client_verify_mode = mode;
    }

    return NULL;
}

#define INIT_CA_SIZE 128

const char *mgs_set_client_ca_file(cmd_parms * parms, void *dummy,
        const char *arg) {
    int rv;
    const char *file;
    apr_pool_t *spool;
    gnutls_datum_t data;

    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);
    apr_pool_create(&spool, parms->pool);

    file = ap_server_root_relative(spool, arg);

    if (load_datum_from_file(spool, file, &data) != 0) {
        return apr_psprintf(parms->pool, "GnuTLS: Error Reading "
                "Client CA File '%s'", file);
    }

    sc->ca_list_size = INIT_CA_SIZE;
    sc->ca_list = malloc(sc->ca_list_size * sizeof (*sc->ca_list));
    if (sc->ca_list == NULL) {
        return apr_psprintf(parms->pool,
                "mod_gnutls: Memory allocation error");
    }

    rv = gnutls_x509_crt_list_import(sc->ca_list, &sc->ca_list_size,
            &data, GNUTLS_X509_FMT_PEM,
            GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
    if (rv < 0 && rv != GNUTLS_E_SHORT_MEMORY_BUFFER) {
        return apr_psprintf(parms->pool, "GnuTLS: Failed to load "
                "Client CA File '%s': (%d) %s", file,
                rv, gnutls_strerror(rv));
    }

    if (INIT_CA_SIZE < sc->ca_list_size) {
        sc->ca_list =
                realloc(sc->ca_list,
                sc->ca_list_size * sizeof (*sc->ca_list));
        if (sc->ca_list == NULL) {
            return apr_psprintf(parms->pool,
                    "mod_gnutls: Memory allocation error");
        }

        /* re-read */
        rv = gnutls_x509_crt_list_import(sc->ca_list,
                &sc->ca_list_size, &data,
                GNUTLS_X509_FMT_PEM, 0);

        if (rv < 0) {
            return apr_psprintf(parms->pool,
                    "GnuTLS: Failed to load "
                    "Client CA File '%s': (%d) %s",
                    file, rv, gnutls_strerror(rv));
        }
    }

    apr_pool_destroy(spool);
    return NULL;
}

const char *mgs_set_keyring_file(cmd_parms * parms, void *dummy,
        const char *arg) {
    int rv;
    const char *file;
    apr_pool_t *spool;
    gnutls_datum_t data;

    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);
    apr_pool_create(&spool, parms->pool);

    file = ap_server_root_relative(spool, arg);

    if (load_datum_from_file(spool, file, &data) != 0) {
        return apr_psprintf(parms->pool, "GnuTLS: Error Reading "
                "Keyring File '%s'", file);
    }

    rv = gnutls_openpgp_keyring_init(&sc->pgp_list);
    if (rv < 0) {
        return apr_psprintf(parms->pool,
                "GnuTLS: Failed to initialize"
                "keyring: (%d) %s", rv,
                gnutls_strerror(rv));
    }

    rv = gnutls_openpgp_keyring_import(sc->pgp_list, &data,
            GNUTLS_OPENPGP_FMT_BASE64);
    if (rv < 0) {
        return apr_psprintf(parms->pool, "GnuTLS: Failed to load "
                "Keyring File '%s': (%d) %s", file, rv,
                gnutls_strerror(rv));
    }

    apr_pool_destroy(spool);
    return NULL;
}

const char *mgs_set_proxy_engine(cmd_parms * parms, void *dummy,
        const char *arg) {
    
    mgs_srvconf_rec *sc =(mgs_srvconf_rec *) 
            ap_get_module_config(parms->server->module_config, &gnutls_module);
    
    if (!strcasecmp(arg, "On")) {
        sc->proxy_enabled = GNUTLS_ENABLED_TRUE;
    } else if (!strcasecmp(arg, "Off")) {
        sc->proxy_enabled = GNUTLS_ENABLED_FALSE;
    } else {
        return "SSLProxyEngine must be set to 'On' or 'Off'";
    }

    return NULL;
}

const char *mgs_set_enabled(cmd_parms * parms, void *dummy,
        const char *arg) {
    mgs_srvconf_rec *sc =
            (mgs_srvconf_rec *) ap_get_module_config(parms->server->
            module_config,
            &gnutls_module);
    if (!strcasecmp(arg, "On")) {
        sc->enabled = GNUTLS_ENABLED_TRUE;
    } else if (!strcasecmp(arg, "Off")) {
        sc->enabled = GNUTLS_ENABLED_FALSE;
    } else {
        return "GnuTLSEnable must be set to 'On' or 'Off'";
    }

    return NULL;
}

const char *mgs_set_export_certificates_enabled(cmd_parms * parms, void *dummy, const char *arg) {
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) ap_get_module_config(parms->server->module_config, &gnutls_module);
    if (!strcasecmp(arg, "On")) {
        sc->export_certificates_enabled = GNUTLS_ENABLED_TRUE;
    } else if (!strcasecmp(arg, "Off")) {
        sc->export_certificates_enabled = GNUTLS_ENABLED_FALSE;
    } else {
        return
        "GnuTLSExportCertificates must be set to 'On' or 'Off'";
    }

    return NULL;
}

const char *mgs_set_priorities(cmd_parms * parms, void *dummy, const char *arg) {

	int ret;
    const char *err;

    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) 
						  ap_get_module_config(parms->server->module_config, &gnutls_module);

    ret = gnutls_priority_init(&sc->priorities, arg, &err);

    if (ret < 0) {
        if (ret == GNUTLS_E_INVALID_REQUEST) {
            return apr_psprintf(parms->pool, 
								"GnuTLS: Syntax error parsing priorities string at: %s", err);
		}
        return "Error setting priorities";
    }

    return NULL;
}

static mgs_srvconf_rec *_mgs_config_server_create(apr_pool_t * p, char** err) {
    mgs_srvconf_rec *sc = apr_pcalloc(p, sizeof (*sc));
    int ret;

    sc->enabled = GNUTLS_ENABLED_UNSET;

    ret = gnutls_certificate_allocate_credentials(&sc->certs);
    if (ret < 0) {
        *err = apr_psprintf(p, "GnuTLS: Failed to initialize"
                            ": (%d) %s", ret,
                            gnutls_strerror(ret));
        return NULL;
    }

    ret = gnutls_anon_allocate_server_credentials(&sc->anon_creds);
    if (ret < 0) {
        *err = apr_psprintf(p, "GnuTLS: Failed to initialize"
                            ": (%d) %s", ret,
                            gnutls_strerror(ret));
        return NULL;
    }
#ifdef ENABLE_SRP
    ret = gnutls_srp_allocate_server_credentials(&sc->srp_creds);
    if (ret < 0) {
        *err =  apr_psprintf(p, "GnuTLS: Failed to initialize"
                             ": (%d) %s", ret,
                             gnutls_strerror(ret));
        return NULL;
    }

    sc->srp_tpasswd_conf_file = NULL;
    sc->srp_tpasswd_file = NULL;
#endif

    sc->privkey_x509 = NULL;
	/* Initialize all Certificate Chains */
    /* FIXME: how do we indicate that this is unset for a merge? (that
     * is, how can a subordinate server override the chain by setting
     * an empty one?  what would that even look like in the
     * configuration?) */
	sc->certs_x509_chain = malloc(MAX_CHAIN_SIZE * sizeof (*sc->certs_x509_chain));
    sc->certs_x509_chain_num = 0;
    sc->cache_timeout = -1; /* -1 means "unset" */
    sc->cache_type = mgs_cache_unset;
    sc->cache_config = NULL;
    sc->tickets = GNUTLS_ENABLED_UNSET;
    sc->priorities = NULL;
    sc->dh_params = NULL;
    sc->proxy_enabled = GNUTLS_ENABLED_UNSET;
    sc->export_certificates_enabled = GNUTLS_ENABLED_UNSET;
    sc->client_verify_method = mgs_cvm_unset; 
    
/* this relies on GnuTLS never changing the gnutls_certificate_request_t enum to define -1 */
    sc->client_verify_mode = -1; 

    return sc;
}

void *mgs_config_server_create(apr_pool_t * p, server_rec * s) {
    char *err = NULL;
    mgs_srvconf_rec *sc = _mgs_config_server_create(p, &err);
    if (sc) return sc; else return err;
}

#define gnutls_srvconf_merge(t, unset) sc->t = (add->t == unset) ? base->t : add->t
#define gnutls_srvconf_assign(t) sc->t = add->t

void *mgs_config_server_merge(apr_pool_t *p, void *BASE, void *ADD) {
    int i;
    char *err = NULL;
    mgs_srvconf_rec *base = (mgs_srvconf_rec *)BASE;
    mgs_srvconf_rec *add = (mgs_srvconf_rec *)ADD;
    mgs_srvconf_rec *sc = _mgs_config_server_create(p, &err);
    if (NULL == sc) return err;

    gnutls_srvconf_merge(enabled, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_merge(tickets, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_merge(proxy_enabled, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_merge(export_certificates_enabled, GNUTLS_ENABLED_UNSET);
    gnutls_srvconf_merge(client_verify_method, mgs_cvm_unset);
    gnutls_srvconf_merge(client_verify_mode, -1);
    gnutls_srvconf_merge(srp_tpasswd_file, NULL);
    gnutls_srvconf_merge(srp_tpasswd_conf_file, NULL);
    gnutls_srvconf_merge(privkey_x509, NULL);
    gnutls_srvconf_merge(priorities, NULL);
    gnutls_srvconf_merge(dh_params, NULL);

    /* FIXME: the following items are pre-allocated, and should be
     * properly disposed of before assigning in order to avoid leaks;
     * so at the moment, we can't actually have them in the config.
     * what happens during de-allocation? 

     * This is probably leaky.
     */
    gnutls_srvconf_assign(certs);
    gnutls_srvconf_assign(anon_creds);
    gnutls_srvconf_assign(srp_creds);
    gnutls_srvconf_assign(certs_x509_chain);
    gnutls_srvconf_assign(certs_x509_chain_num);

    /* how do these get transferred cleanly before the data from ADD
     * goes away? */
    gnutls_srvconf_assign(cert_cn);
    for (i = 0; i < MAX_CERT_SAN; i++)
        gnutls_srvconf_assign(cert_san[i]);
    gnutls_srvconf_assign(ca_list);
    gnutls_srvconf_assign(ca_list_size);
    gnutls_srvconf_assign(cert_pgp);
    gnutls_srvconf_assign(pgp_list);
    gnutls_srvconf_assign(privkey_pgp);

    return sc;
}

#undef gnutls_srvconf_merge
#undef gnutls_srvconf_assign

void *mgs_config_dir_merge(apr_pool_t * p, void *basev, void *addv) {
    mgs_dirconf_rec *new;
    /*    mgs_dirconf_rec *base = (mgs_dirconf_rec *) basev; */
    mgs_dirconf_rec *add = (mgs_dirconf_rec *) addv;

    new = (mgs_dirconf_rec *) apr_pcalloc(p, sizeof (mgs_dirconf_rec));
    new->client_verify_mode = add->client_verify_mode;
    return new;
}

void *mgs_config_dir_create(apr_pool_t * p, char *dir) {
    mgs_dirconf_rec *dc = apr_palloc(p, sizeof (*dc));
    dc->client_verify_mode = -1;
    return dc;
}


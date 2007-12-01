/**
 *  Copyright 2004-2005 Paul Querna
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
				const char *file, gnutls_datum_t * data)
{
    apr_file_t *fp;
    apr_finfo_t finfo;
    apr_status_t rv;
    apr_size_t br = 0;

    rv = apr_file_open(&fp, file, APR_READ | APR_BINARY, APR_OS_DEFAULT,
		       pool);
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
			    const char *arg)
{
    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->server->
						 module_config,
						 &gnutls_module);

    sc->dh_params_file = ap_server_root_relative(parms->pool, arg);

    return NULL;
}

const char *mgs_set_rsa_export_file(cmd_parms * parms, void *dummy,
				    const char *arg)
{
    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->server->
						 module_config,
						 &gnutls_module);

    sc->rsa_params_file = ap_server_root_relative(parms->pool, arg);

    return NULL;
}


const char *mgs_set_cert_file(cmd_parms * parms, void *dummy,
			      const char *arg)
{
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

    gnutls_x509_crt_init(&sc->cert_x509);
    ret =
	gnutls_x509_crt_import(sc->cert_x509, &data, GNUTLS_X509_FMT_PEM);
    if (ret != 0) {
	return apr_psprintf(parms->pool, "GnuTLS: Failed to Import "
			    "Certificate'%s': (%d) %s", file, ret,
			    gnutls_strerror(ret));
    }

    apr_pool_destroy(spool);
    return NULL;
}

const char *mgs_set_key_file(cmd_parms * parms, void *dummy,
			     const char *arg)
{
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

    gnutls_x509_privkey_init(&sc->privkey_x509);
    ret =
	gnutls_x509_privkey_import(sc->privkey_x509, &data,
				   GNUTLS_X509_FMT_PEM);
    if (ret != 0) {
	return apr_psprintf(parms->pool, "GnuTLS: Failed to Import "
			    "Private Key '%s': (%d) %s", file, ret,
			    gnutls_strerror(ret));
    }
    apr_pool_destroy(spool);
    return NULL;
}

const char *mgs_set_srp_tpasswd_file(cmd_parms * parms, void *dummy,
				     const char *arg)
{
    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->server->
						 module_config,
						 &gnutls_module);

    sc->srp_tpasswd_file = ap_server_root_relative(parms->pool, arg);

    return NULL;
}

const char *mgs_set_srp_tpasswd_conf_file(cmd_parms * parms, void *dummy,
					  const char *arg)
{
    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->server->
						 module_config,
						 &gnutls_module);

    sc->srp_tpasswd_conf_file = ap_server_root_relative(parms->pool, arg);

    return NULL;
}

const char *mgs_set_cache(cmd_parms * parms, void *dummy,
			  const char *type, const char *arg)
{
    const char *err;
    mgs_srvconf_rec *sc = ap_get_module_config(parms->server->
					       module_config,
					       &gnutls_module);
    if ((err = ap_check_cmd_context(parms, GLOBAL_ONLY))) {
	return err;
    }

    if (strcasecmp("none", type) == 0) {
	sc->cache_type = mgs_cache_none;
    } else if (strcasecmp("dbm", type) == 0) {
	sc->cache_type = mgs_cache_dbm;
    }
#if HAVE_APR_MEMCACHE
    else if (strcasecmp("memcache", type) == 0) {
	sc->cache_type = mgs_cache_memcache;
    }
#endif
    else {
	return "Invalid Type for GnuTLSCache!";
    }

    if (sc->cache_type == mgs_cache_dbm) {
	sc->cache_config = ap_server_root_relative(parms->pool, arg);
    } else {
	sc->cache_config = apr_pstrdup(parms->pool, arg);
    }

    return NULL;
}

const char *mgs_set_cache_timeout(cmd_parms * parms, void *dummy,
				  const char *arg)
{
    int argint;
    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->server->
						 module_config,
						 &gnutls_module);

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

const char *mgs_set_client_verify(cmd_parms * parms, void *dummy,
				  const char *arg)
{
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
	    (mgs_srvconf_rec *) ap_get_module_config(parms->server->
						     module_config,
						     &gnutls_module);
	sc->client_verify_mode = mode;
    }

    return NULL;
}

const char *mgs_set_client_ca_file(cmd_parms * parms, void *dummy,
				   const char *arg)
{
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

    sc->ca_list_size = MAX_CA_CRTS;
    rv = gnutls_x509_crt_list_import(sc->ca_list, &sc->ca_list_size,
				     &data, GNUTLS_X509_FMT_PEM,
				     GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
    if (rv < 0) {
	return apr_psprintf(parms->pool, "GnuTLS: Failed to load "
			    "Client CA File '%s': (%d) %s", file, rv,
			    gnutls_strerror(rv));
    }

    apr_pool_destroy(spool);
    return NULL;
}

const char *mgs_set_enabled(cmd_parms * parms, void *dummy,
			    const char *arg)
{
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

const char *mgs_set_export_certificates_enabled(cmd_parms * parms, void *dummy,
			    const char *arg)
{
    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->server->
						 module_config,
						 &gnutls_module);
    if (!strcasecmp(arg, "On")) {
	sc->export_certificates_enabled = GNUTLS_ENABLED_TRUE;
    } else if (!strcasecmp(arg, "Off")) {
	sc->export_certificates_enabled = GNUTLS_ENABLED_FALSE;
    } else {
	return "GnuTLSExportCertificates must be set to 'On' or 'Off'";
    }

    return NULL;
}


const char *mgs_set_priorities(cmd_parms * parms, void *dummy, const char *arg)
{
    int ret;
    const char *err;
    mgs_srvconf_rec *sc =
	(mgs_srvconf_rec *) ap_get_module_config(parms->server->
						 module_config,
						 &gnutls_module);


    ret = gnutls_priority_init( &sc->priorities, arg, &err);
    if (ret < 0) {
      if (ret == GNUTLS_E_INVALID_REQUEST)
	return apr_psprintf(parms->pool, "GnuTLS: Syntax error parsing priorities string at: %s", err);
      return "Error setting priorities";
    }

    return NULL;
}

void *mgs_config_server_create(apr_pool_t * p, server_rec * s)
{
    mgs_srvconf_rec *sc = apr_pcalloc(p, sizeof(*sc));

    sc->enabled = GNUTLS_ENABLED_FALSE;

    gnutls_certificate_allocate_credentials(&sc->certs);
    gnutls_anon_allocate_server_credentials(&sc->anon_creds);
    gnutls_srp_allocate_server_credentials(&sc->srp_creds);

    sc->srp_tpasswd_conf_file = NULL;
    sc->srp_tpasswd_file = NULL;
    sc->privkey_x509 = NULL;
    sc->cert_x509 = NULL;
    sc->cache_timeout = apr_time_from_sec(300);
    sc->cache_type = mgs_cache_dbm;
    sc->cache_config = ap_server_root_relative(p, "conf/gnutls_cache");

    sc->dh_params_file = ap_server_root_relative(p, "conf/dhfile");
    sc->rsa_params_file = ap_server_root_relative(p, "conf/rsafile");

    sc->client_verify_mode = GNUTLS_CERT_IGNORE;

    return sc;
}

void *mgs_config_dir_merge(apr_pool_t * p, void *basev, void *addv)
{
    mgs_dirconf_rec *new;
/*    mgs_dirconf_rec *base = (mgs_dirconf_rec *) basev; */
    mgs_dirconf_rec *add = (mgs_dirconf_rec *) addv;

    new = (mgs_dirconf_rec *) apr_pcalloc(p, sizeof(mgs_dirconf_rec));
    new->lua_bytecode = apr_pstrmemdup(p, add->lua_bytecode,
				       add->lua_bytecode_len);
    new->lua_bytecode_len = add->lua_bytecode_len;
    new->client_verify_mode = add->client_verify_mode;
    return new;
}

void *mgs_config_dir_create(apr_pool_t * p, char *dir)
{
    mgs_dirconf_rec *dc = apr_palloc(p, sizeof(*dc));

    dc->client_verify_mode = -1;
    dc->lua_bytecode = NULL;
    dc->lua_bytecode_len = 0;
    return dc;
}

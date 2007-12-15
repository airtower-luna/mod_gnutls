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


static void gnutls_hooks(apr_pool_t * p)
{
    ap_hook_pre_connection(mgs_hook_pre_connection, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_post_config(mgs_hook_post_config, NULL, NULL,
                        APR_HOOK_MIDDLE);
    ap_hook_child_init(mgs_hook_child_init, NULL, NULL,
                       APR_HOOK_MIDDLE);
#if USING_2_1_RECENT
    ap_hook_http_scheme(mgs_hook_http_scheme, NULL, NULL,
                        APR_HOOK_MIDDLE);
#else
    ap_hook_http_method(mgs_hook_http_scheme, NULL, NULL,
                        APR_HOOK_MIDDLE);
#endif
    ap_hook_default_port(mgs_hook_default_port, NULL, NULL,
                         APR_HOOK_MIDDLE);
    ap_hook_pre_config(mgs_hook_pre_config, NULL, NULL,
                       APR_HOOK_MIDDLE);
    
    ap_hook_access_checker(mgs_hook_authz, NULL, NULL, APR_HOOK_REALLY_FIRST);
    
    ap_hook_fixups(mgs_hook_fixups, NULL, NULL, APR_HOOK_REALLY_FIRST);
    
    /* TODO: HTTP Upgrade Filter */
    /* ap_register_output_filter ("UPGRADE_FILTER", 
     *          ssl_io_filter_Upgrade, NULL, AP_FTYPE_PROTOCOL + 5);
     */

    ap_register_input_filter(GNUTLS_INPUT_FILTER_NAME,
                             mgs_filter_input, NULL,
                             AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter(GNUTLS_OUTPUT_FILTER_NAME,
                              mgs_filter_output, NULL,
                              AP_FTYPE_CONNECTION + 5);
}

static const command_rec mgs_config_cmds[] = {
    AP_INIT_TAKE1("GnuTLSClientVerify", mgs_set_client_verify,
                  NULL,
                  RSRC_CONF|OR_AUTHCFG,
                  "Set Verification Requirements of the Client Certificate"),
    AP_INIT_TAKE1("GnuTLSClientCAFile", mgs_set_client_ca_file,
                  NULL,
                  RSRC_CONF,
                  "Set the CA File to verify Client Certificates"),
    AP_INIT_TAKE1("GnuTLSPGPKeyringFile", mgs_set_keyring_file,
                  NULL,
                  RSRC_CONF,
                  "Set the Keyring File to verify Client Certificates"),
    AP_INIT_TAKE1("GnuTLSDHFile", mgs_set_dh_file,
                  NULL,
                  RSRC_CONF,
                  "Set the file to read Diffie Hellman parameters from"),
    AP_INIT_TAKE1("GnuTLSRSAFile", mgs_set_rsa_export_file,
                  NULL,
                  RSRC_CONF,
                  "Set the file to read RSA-EXPORT parameters from"),
    AP_INIT_TAKE1("GnuTLSCertificateFile", mgs_set_cert_file,
                  NULL,
                  RSRC_CONF,
                  "SSL Server Certificate file"),
    AP_INIT_TAKE1("GnuTLSKeyFile", mgs_set_key_file,
                  NULL,
                  RSRC_CONF,
                  "SSL Server Private Key file"),
    AP_INIT_TAKE1("GnuTLSPGPCertificateFile", mgs_set_pgpcert_file,
                  NULL,
                  RSRC_CONF,
                  "SSL Server PGP Certificate file"),
    AP_INIT_TAKE1("GnuTLSPGPKeyFile", mgs_set_pgpkey_file,
                  NULL,
                  RSRC_CONF,
                  "SSL Server PGP Private key file"),
    AP_INIT_TAKE1("GnuTLSSRPPasswdFile", mgs_set_srp_tpasswd_file,
                  NULL,
                  RSRC_CONF,
                  "SSL Server SRP Password Conf file"),
    AP_INIT_TAKE1("GnuTLSSRPPasswdConfFile", mgs_set_srp_tpasswd_conf_file,
                  NULL,
                  RSRC_CONF,
                  "SSL Server SRP Parameters file"),
    AP_INIT_TAKE1("GnuTLSCacheTimeout", mgs_set_cache_timeout,
                  NULL,
                  RSRC_CONF,
                  "Cache Timeout"),
    AP_INIT_TAKE2("GnuTLSCache", mgs_set_cache,
                  NULL,
                  RSRC_CONF,
                  "Cache Configuration"),
    AP_INIT_RAW_ARGS("GnuTLSPriorities", mgs_set_priorities,
                  NULL,
                  RSRC_CONF,
                  "The priorities to enable (ciphers, Key exchange, macs, compression)."),
    AP_INIT_TAKE1("GnuTLSEnable", mgs_set_enabled,
                  NULL,
                  RSRC_CONF,
                  "Whether this server has GnuTLS Enabled. Default: Off"),
    AP_INIT_TAKE1("GnuTLSExportCertificates", mgs_set_export_certificates_enabled,
                  NULL,
                  RSRC_CONF,
                  "Whether to export PEM encoded certificates to CGIs. Default: Off"),
#if 0
    AP_INIT_RAW_ARGS("<GnuTLSRequire", mgs_set_require_section,
                  NULL,
                  EXEC_ON_READ|OR_ALL,
                  "Whether this server has GnuTLS Enabled. Default: Off"),
    AP_INIT_RAW_ARGS("GnuTLSRequireByteCode", mgs_set_require_bytecode,
                     NULL,
                     OR_ALL,
                     "Internal Command for reading Lua Bytecode."),
#endif
    {NULL}
};

module AP_MODULE_DECLARE_DATA gnutls_module = {
    STANDARD20_MODULE_STUFF,
    mgs_config_dir_create,
    mgs_config_dir_merge,
    mgs_config_server_create,
    NULL,
    mgs_config_cmds,
    gnutls_hooks
};

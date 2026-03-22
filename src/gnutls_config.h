/*
 *  Copyright 2016-2026 Fiona Klute
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

#ifndef __MOD_GNUTLS_CONFIG_H__
#define __MOD_GNUTLS_CONFIG_H__

#include "mod_gnutls.h"
#include <httpd.h>

/* timeouts as defined in mgs_set_timeout() cannot be negative */
#define MGS_TIMEOUT_UNSET -1

/**
 * Perform any reinitialization required in PKCS #11
 */
int mgs_pkcs11_reinit(server_rec * s);

/* Loads all files set in the configuration */
int mgs_load_files(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s)
    __attribute__((nonnull));

const char *mgs_set_dh_file(cmd_parms * parms, void *dummy,
                                        const char *arg);
const char *mgs_set_cert_file(cmd_parms * parms, void *dummy,
                                        const char *arg);

const char *mgs_set_key_file(cmd_parms * parms, void *dummy,
                             const char *arg);

const char *mgs_set_timeout(cmd_parms *parms, void *dummy, const char *arg);

const char *mgs_set_client_verify(cmd_parms * parms, void *dummy,
                                  const char *arg);

const char *mgs_set_client_ca_file(cmd_parms * parms, void *dummy,
                                   const char *arg);

const char *mgs_set_client_key_purpose(cmd_parms * parms, void *dummy,
                                       const char *arg);

const char *mgs_set_p11_module(cmd_parms * parms, void *dummy,
                               const char *arg);

const char *mgs_set_pin(cmd_parms * parms, void *dummy,
                                   const char *arg);

const char *mgs_set_srk_pin(cmd_parms * parms, void *dummy,
                                   const char *arg);

const char *mgs_set_enabled(cmd_parms * parms, void *dummy,
                            const int arg);
const char *mgs_set_export_certificates_size(cmd_parms * parms, void *dummy,
                            const char *arg);
const char *mgs_set_priorities(cmd_parms * parms, void *dummy,
                            const char *arg);
const char *mgs_set_tickets(cmd_parms * parms, void *dummy,
                            const int arg);

void *mgs_config_server_create(apr_pool_t * p, server_rec * s);
void *mgs_config_server_merge(apr_pool_t *p, void *BASE, void *ADD);

void *mgs_config_dir_merge(apr_pool_t *p, void *basev, void *addv);

void *mgs_config_dir_create(apr_pool_t *p, char *dir);

const char *mgs_store_cred_path(cmd_parms * parms,
                                void *dummy __attribute__((unused)),
                                const char *arg);

const char *mgs_set_cache(cmd_parms * parms, void *dummy,
                          const char *type, const char* arg);

#endif /* __MOD_GNUTLS_CONFIG_H__ */

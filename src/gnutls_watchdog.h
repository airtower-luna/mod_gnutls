/*
 *  Copyright 2018 Fiona Klute
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

#ifndef __MOD_GNUTLS_WATCHDOG_H__
#define __MOD_GNUTLS_WATCHDOG_H__

#include <httpd.h>
#include <mod_watchdog.h>

/**
 * Watchdog object including functions
 */
struct mgs_watchdog {
    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *get_instance;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *register_callback;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_set_callback_interval) *set_callback_interval;
    ap_watchdog_t *wd;
};

/**
 * Creates a new mgs_watchdog structure and initializes the
 * included `apr_watchdog_t` with the named singleton watchdog.
 *
 * @param s server reference for logging
 * @param name watchdog name
 * @param p memory pool for the watchdog
 *
 * @return pointer to the new mgs_watchdog, or `NULL` on error
 */
struct mgs_watchdog* mgs_new_singleton_watchdog(server_rec *s, char *name,
                                                apr_pool_t *p);

#endif /* __MOD_GNUTLS_WATCHDOG_H__ */

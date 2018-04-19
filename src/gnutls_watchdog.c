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

#include "gnutls_watchdog.h"

#include <httpd.h>
#include <mod_watchdog.h>


struct mgs_watchdog* mgs_new_singleton_watchdog(server_rec *s, char *name,
                                                apr_pool_t* p)
{
    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *inst_fn =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *reg_callback_fn =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    APR_OPTIONAL_FN_TYPE(ap_watchdog_set_callback_interval) *mod_callback_fn =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_set_callback_interval);

    /* Check if all functions are available */
    if (inst_fn == NULL || reg_callback_fn == NULL || mod_callback_fn == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_WARNING, APR_EGENERAL, s,
                     "Could not retrieve watchdog functions, has "
                     "mod_watchdog been loaded?");
        return NULL;
    }

    apr_pool_t *wd_pool;
    apr_status_t rv = apr_pool_create(&wd_pool, p);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Creating pool for watchdog instance failed!");
        return NULL;
    }

    struct mgs_watchdog *w = apr_palloc(wd_pool, sizeof(struct mgs_watchdog));

    w->get_instance = inst_fn;
    w->register_callback = reg_callback_fn;
    w->set_callback_interval = mod_callback_fn;

    /* 0 -> run in child process, 1 -> singleton watchdog */
    rv = w->get_instance(&w->wd, name, 0, 1, wd_pool);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Retrieving watchdog instance '%s' failed!", name);
        apr_pool_destroy(wd_pool);
        return NULL;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s,
                 "watchdog init for %s", name);
    return w;
}

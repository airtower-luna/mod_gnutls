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

#ifndef __MOD_GNUTLS_CONFIG_H__
#define __MOD_GNUTLS_CONFIG_H__

#include "mod_gnutls.h"
#include <httpd.h>

/* timeouts as defined in mgs_set_timeout() cannot be negative */
#define MGS_TIMEOUT_UNSET -1

/* TODO: move configuration related function definitions from
 * mod_gnutls.h.in over here */

const char *mgs_set_cache(cmd_parms * parms, void *dummy,
                          const char *type, const char* arg);

#endif /* __MOD_GNUTLS_CONFIG_H__ */

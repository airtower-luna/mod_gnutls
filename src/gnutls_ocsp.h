/**
 *  Copyright 2016 Thomas Klute
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

#ifndef __MOD_GNUTLS_OCSP_H__
#define __MOD_GNUTLS_OCSP_H__

#include "gnutls/gnutls.h"
#include "httpd.h"
#include "http_config.h"

const char *mgs_store_ocsp_response_path(cmd_parms * parms,
                                         void *dummy __attribute__((unused)),
                                         const char *arg);

int mgs_get_ocsp_response(gnutls_session_t session, void *ptr,
                          gnutls_datum_t *ocsp_response);

#endif /* __MOD_GNUTLS_OCSP_H__ */

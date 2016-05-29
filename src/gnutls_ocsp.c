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

#include "gnutls_ocsp.h"

#include "mod_gnutls.h"
#include "apr_lib.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

const char *mgs_store_ocsp_response_path(cmd_parms *parms,
                                         void *dummy __attribute__((unused)),
                                         const char *arg)
{
    mgs_srvconf_rec *sc = (mgs_srvconf_rec *)
        ap_get_module_config(parms->server->module_config, &gnutls_module);

    sc->ocsp_response_file = ap_server_root_relative(parms->pool, arg);
    return NULL;
}

int mgs_get_ocsp_response(gnutls_session_t session __attribute__((unused)),
                          void *ptr,
                          gnutls_datum_t *ocsp_response)
{
    mgs_handle_t *ctxt = (mgs_handle_t *) ptr;
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c,
                  "Loading OCSP response from %s",
                  ctxt->sc->ocsp_response_file);

    int ret = gnutls_load_file(ctxt->sc->ocsp_response_file, ocsp_response);
    if (ret != GNUTLS_E_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, ctxt->c,
                      "Loading OCSP response failed: %s (%d)",
                      gnutls_strerror(ret), ret);
        gnutls_free(ocsp_response->data);
        ocsp_response->size = 0;
        ocsp_response->data = NULL;
        return GNUTLS_E_NO_CERTIFICATE_STATUS;
    }

    return GNUTLS_E_SUCCESS;
}

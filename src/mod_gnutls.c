/* ====================================================================
 *  Copyright 2004 Paul Querna
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

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_buckets.h"
#include "apr_strings.h"
#include "apr_tables.h"

#include <gcrypt.h>
#include <gnutls/gnutls.h>

#if APR_HAS_THREADS
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

module AP_MODULE_DECLARE_DATA gnutls_module;

#define GNUTLS_OUTPUT_FILTER_NAME "GnuTLS Output Filter"
#define GNUTLS_INPUT_FILTER_NAME "GnuTLS Input Filter"

#define GNUTLS_ENABLED_FALSE 0
#define GNUTLS_ENABLED_TRUE  1


typedef struct gnutls_srvconf_t gnutls_srvconf_t;
struct gnutls_srvconf_t
{
    gnutls_certificate_credentials_t certs;
    char *key_file;
    char *cert_file;
    int enabled;
};

typedef struct gnutls_handle_t gnutls_handle_t;
struct gnutls_handle_t
{
    gnutls_srvconf_t *sc;
    gnutls_session_t session;
    ap_filter_t *input_filter;
    apr_bucket_brigade *input_bb;
    apr_read_type_e input_block;
};

static apr_status_t gnutls_filter_input(ap_filter_t * f,
                                        apr_bucket_brigade * bb,
                                        ap_input_mode_t mode,
                                        apr_read_type_e block,
                                        apr_off_t readbytes)
{
    apr_status_t status = APR_SUCCESS;
    gnutls_handle_t *ctxt = (gnutls_handle_t *) f->ctx;

    if (f->c->aborted) {
        apr_bucket *bucket = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
        return APR_ECONNABORTED;
    }

    return status;
}

static apr_status_t gnutls_filter_output(ap_filter_t * f,
                                         apr_bucket_brigade * bb)
{
    apr_bucket *b;
    const char *buf = 0;
    apr_size_t bytes = 0;
    gnutls_handle_t *ctxt = (gnutls_handle_t *) f->ctx;
    apr_status_t status = APR_SUCCESS;

    if (!ctxt) {
        /* first run. */
    }

    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_EOS(b)) {
            /* end of connection */
        }
        else if (apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ)
                 == APR_SUCCESS) {
            /* more data */
        }
    }

    return status;
}

static apr_status_t gnutls_cleanup_pre_config(void *data)
{
    gnutls_global_deinit();
    return APR_SUCCESS;
}

static int gnutls_hook_pre_config(apr_pool_t * pconf,
                                  apr_pool_t * plog, apr_pool_t * ptemp)
{

#if APR_HAS_THREADS
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif

    gnutls_global_init();

    apr_pool_cleanup_register(pconf, NULL, gnutls_cleanup_pre_config,
                              apr_pool_cleanup_null);

    return OK;
}

#define DH_BITS 1024
#define RSA_BITS 512

static int gnutls_hook_post_config(apr_pool_t * p, apr_pool_t * plog,
                                   apr_pool_t * ptemp,
                                   server_rec * base_server)
{
    gnutls_srvconf_t *sc;
    server_rec *s;
    gnutls_dh_params_t dh_params;
    gnutls_rsa_params_t rsa_params;


    /* TODO: Should we regenerate these after X requests / X time ? */
    gnutls_dh_params_init(&dh_params);
    gnutls_dh_params_generate2(dh_params, DH_BITS);
    gnutls_rsa_params_init(&rsa_params);
    gnutls_rsa_params_generate2(rsa_params, RSA_BITS);

    for (s = base_server; s; s = s->next) {
        sc = (gnutls_srvconf_t *) ap_get_module_config(s->module_config,
                                                       &gnutls_module);
        if (sc->cert_file != NULL && sc->key_file != NULL) {
            gnutls_certificate_set_x509_key_file(sc->certs, sc->cert_file,
                                                 sc->key_file,
                                                 GNUTLS_X509_FMT_PEM);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                         "[GnuTLS] - Host '%s' is missing a Cert and Key File!",
                         s->server_hostname);
        }

        /**
         * TODO: Is it okay for all virtual hosts to 
         *       share the same DH/RSAparams? 
         */
        gnutls_certificate_set_dh_params(sc->certs, dh_params);
        gnutls_certificate_set_rsa_export_params(sc->certs, rsa_params);
    }

    ap_add_version_component(p, "GnuTLS/" LIBGNUTLS_VERSION);
    return OK;
}

static const char *gnutls_hook_http_method(const request_rec * r)
{
    gnutls_srvconf_t *sc =
        (gnutls_srvconf_t *) ap_get_module_config(r->server->module_config,
                                                  &gnutls_module);

    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return NULL;
    }

    return "https";
}

static apr_port_t gnutls_hook_default_port(const request_rec * r)
{
    gnutls_srvconf_t *sc =
        (gnutls_srvconf_t *) ap_get_module_config(r->server->module_config,
                                                  &gnutls_module);

    if (sc->enabled == GNUTLS_ENABLED_FALSE) {
        return 0;
    }

    return 443;
}

/**
 * From mod_ssl / ssl_engine_io.c
 * This function will read from a brigade and discard the read buckets as it
 * proceeds.  It will read at most *len bytes.
 */
static apr_status_t brigade_consume(apr_bucket_brigade * bb,
                                    apr_read_type_e block,
                                    char *c, apr_size_t * len)
{
    apr_size_t actual = 0;
    apr_status_t status = APR_SUCCESS;

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);
        const char *str;
        apr_size_t str_len;
        apr_size_t consume;

        /* Justin points out this is an http-ism that might
         * not fit if brigade_consume is added to APR.  Perhaps
         * apr_bucket_read(eos_bucket) should return APR_EOF?
         * Then this becomes mainline instead of a one-off.
         */
        if (APR_BUCKET_IS_EOS(b)) {
            status = APR_EOF;
            break;
        }

        /* The reason I'm not offering brigade_consume yet
         * across to apr-util is that the following call
         * illustrates how borked that API really is.  For
         * this sort of case (caller provided buffer) it
         * would be much more trivial for apr_bucket_consume
         * to do all the work that follows, based on the
         * particular characteristics of the bucket we are
         * consuming here.
         */
        status = apr_bucket_read(b, &str, &str_len, block);

        if (status != APR_SUCCESS) {
            if (APR_STATUS_IS_EOF(status)) {
                /* This stream bucket was consumed */
                apr_bucket_delete(b);
                continue;
            }
            break;
        }

        if (str_len > 0) {
            /* Do not block once some data has been consumed */
            block = APR_NONBLOCK_READ;

            /* Assure we don't overflow. */
            consume = (str_len + actual > *len) ? *len - actual : str_len;

            memcpy(c, str, consume);

            c += consume;
            actual += consume;

            if (consume >= b->length) {
                /* This physical bucket was consumed */
                apr_bucket_delete(b);
            }
            else {
                /* Only part of this physical bucket was consumed */
                b->start += consume;
                b->length -= consume;
            }
        }
        else if (b->length == 0) {
            apr_bucket_delete(b);
        }

        /* This could probably be actual == *len, but be safe from stray
         * photons. */
        if (actual >= *len) {
            break;
        }
    }

    *len = actual;
    return status;
}


static ssize_t gnutls_transport_read(gnutls_transport_ptr_t ptr,
                                     void *buffer, size_t len)
{
    gnutls_handle_t *ctxt = ptr;
    apr_status_t rc;
    apr_size_t in = len;
    /* If Len = 0, we don't do anything. */
    if (!len)
        return 0;

    if (APR_BRIGADE_EMPTY(ctxt->input_bb)) {

        rc = ap_get_brigade(ctxt->input_filter->next, ctxt->input_bb,
                            AP_MODE_READBYTES, ctxt->input_block, in);

        /* Not a problem, there was simply no data ready yet.
         */
        if (APR_STATUS_IS_EAGAIN(rc) || APR_STATUS_IS_EINTR(rc)
            || (rc == APR_SUCCESS && APR_BRIGADE_EMPTY(ctxt->input_bb))) {
            return 0;
        }

        if (rc != APR_SUCCESS) {
            /* Unexpected errors discard the brigade */
            apr_brigade_cleanup(ctxt->input_bb);
            ctxt->input_bb = NULL;
            return -1;
        }
    }

//    brigade_consume(ctxt->input_bb, ctxt->input_block, buffer, &len);


    ap_get_brigade(ctxt->input_filter->next, ctxt->input_bb,
                   AP_MODE_READBYTES, ctxt->input_block, len);

    return len;
}

static ssize_t gnutls_transport_write(gnutls_transport_ptr_t ptr,
                                      const void *buffer, size_t len)
{
    gnutls_handle_t *ctxt = ptr;

//    apr_bucket *bucket = apr_bucket_transient_create(in, inl,
//                                                     outctx->bb->
//                                                     bucket_alloc);

    //  outctx->length += inl;
    //APR_BRIGADE_INSERT_TAIL(outctx->bb, bucket);
    return 0;
}

static int gnutls_hook_pre_connection(conn_rec * c, void *csd)
{
#ifndef GNUTLS_AS_FILTER
    int cfd;
#endif
    gnutls_handle_t *ctxt;
    gnutls_srvconf_t *sc =
        (gnutls_srvconf_t *) ap_get_module_config(c->base_server->
                                                  module_config,
                                                  &gnutls_module);

    if (!(sc && (sc->enabled == GNUTLS_ENABLED_TRUE))) {
        return DECLINED;
    }

    ctxt = apr_pcalloc(c->pool, sizeof(*ctxt));

    ctxt->sc = sc;
    gnutls_init(&ctxt->session, GNUTLS_SERVER);

    gnutls_set_default_priority(ctxt->session);

    gnutls_credentials_set(ctxt->session, GNUTLS_CRD_CERTIFICATE, sc->certs);

    gnutls_certificate_server_set_request(ctxt->session, GNUTLS_CERT_REQUEST);

    gnutls_dh_set_prime_bits(ctxt->session, DH_BITS);

    ap_set_module_config(c->conn_config, &gnutls_module, ctxt);

#ifdef GNUTLS_AS_FILTER
    gnutls_transport_set_pull_function(ctxt->session, gnutls_transport_read);
    gnutls_transport_set_push_function(ctxt->session, gnutls_transport_write);
    gnutls_transport_set_ptr(ctxt->session, ctxt);

    ap_add_input_filter(GNUTLS_INPUT_FILTER_NAME, ctxt, NULL, c);
    ap_add_output_filter(GNUTLS_OUTPUT_FILTER_NAME, ctxt, NULL, c);
#else
    apr_os_sock_get(&cfd, csd);
    gnutls_transport_set_ptr(ctxt->session, (gnutls_transport_ptr)cfd);
#endif
    return OK;
}

static const char *gnutls_set_ca_file(cmd_parms * parms, void *dummy,
                                      const char *arg)
{
    gnutls_srvconf_t *sc =
        (gnutls_srvconf_t *) ap_get_module_config(parms->server->
                                                  module_config,
                                                  &gnutls_module);
/* TODO: CRL, CAFile */
//    gnutls_certificate_set_x509_trust_file(sc->certs, CAFILE,
//                                         GNUTLS_X509_FMT_PEM);
    return NULL;
}

static const command_rec gnutls_cmds[] = {
    AP_INIT_FLAG("GnuTLSEnable", ap_set_flag_slot,
                 (void *) APR_OFFSETOF(gnutls_srvconf_t, enabled), RSRC_CONF,
                 "Whether this server has GnuTLS Enabled. Default: Off"),
    AP_INIT_TAKE1("GnuTLSCertificateFile", ap_set_string_slot,
                  (void *) APR_OFFSETOF(gnutls_srvconf_t, cert_file),
                  RSRC_CONF,
                  "SSL Server Key file"),
    AP_INIT_TAKE1("GnuTLSKeyFile", ap_set_string_slot,
                  (void *) APR_OFFSETOF(gnutls_srvconf_t, key_file),
                  RSRC_CONF,
                  "SSL Server Certificate file"),
    {NULL}
};

/* TODO: CACertificateFile & Client Authentication
 *    AP_INIT_TAKE1("GnuTLSCACertificateFile", ap_set_server_string_slot,
 *                 (void *) APR_OFFSETOF(gnutls_srvconf_t, key_file), NULL,
 *                 RSRC_CONF,
 *                 "CA"),
 */

static void gnutls_hooks(apr_pool_t * p)
{
    ap_hook_pre_connection(gnutls_hook_pre_connection, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_post_config(gnutls_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_http_method(gnutls_hook_http_method, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port(gnutls_hook_default_port, NULL, NULL,
                         APR_HOOK_MIDDLE);
    ap_hook_pre_config(gnutls_hook_pre_config, NULL, NULL, APR_HOOK_MIDDLE);

    /* TODO: HTTP Upgrade Filter */
    /* ap_register_output_filter ("UPGRADE_FILTER", 
     *          ssl_io_filter_Upgrade, NULL, AP_FTYPE_PROTOCOL + 5);
     */

    ap_register_input_filter(GNUTLS_INPUT_FILTER_NAME, gnutls_filter_input,
                             NULL, AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter(GNUTLS_OUTPUT_FILTER_NAME, gnutls_filter_output,
                              NULL, AP_FTYPE_CONNECTION + 5);

}

static void *gnutls_config_server_create(apr_pool_t * p, server_rec * s)
{
    gnutls_srvconf_t *sc = apr_pcalloc(p, sizeof *sc);

    sc->enabled = GNUTLS_ENABLED_FALSE;

    gnutls_certificate_allocate_credentials(&sc->certs);

    sc->key_file = NULL;
    sc->cert_file = NULL;
    return sc;
}



module AP_MODULE_DECLARE_DATA gnutls_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    gnutls_config_server_create,
    NULL,
/*    gnutls_config_server_merge, */
    gnutls_cmds,
    gnutls_hooks
};

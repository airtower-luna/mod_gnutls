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

#include "mod_gnutls.h"

/**
 * Describe how the GnuTLS Filter system works here 
 *  - It is basicly the same as what mod_ssl uses in that respect.
 */

apr_status_t mod_gnutls_filter_input(ap_filter_t * f,
                                     apr_bucket_brigade * bb,
                                     ap_input_mode_t mode,
                                     apr_read_type_e block,
                                     apr_off_t readbytes)
{
    apr_bucket* b;
    apr_status_t status = APR_SUCCESS;
    gnutls_handle_t *ctxt = (gnutls_handle_t *) f->ctx;

    if (f->c->aborted) {
        apr_bucket *bucket = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
        return APR_ECONNABORTED;
    }

#if 0
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
#endif
    return status;
}

#define GNUTLS_HANDSHAKE_ATTEMPTS 10

apr_status_t mod_gnutls_filter_output(ap_filter_t * f,
                                      apr_bucket_brigade * bb)
{
    int ret, i;
    const char *buf = 0;
    apr_size_t bytes = 0;
    gnutls_handle_t *ctxt = (gnutls_handle_t *) f->ctx;
    apr_status_t status = APR_SUCCESS;
    apr_read_type_e rblock = APR_NONBLOCK_READ;

    if (f->c->aborted) {
        apr_brigade_cleanup(bb);
        return APR_ECONNABORTED;
    }

    if (ctxt->status == 0) {
        for (i = GNUTLS_HANDSHAKE_ATTEMPTS; i > 0; i--) {
            ret = gnutls_handshake(ctxt->session);

            if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
                continue;
            }

            if (ret < 0) {
                if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
                    || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
                    ret = gnutls_alert_get(ctxt->session);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                                 "GnuTLS: Hanshake Alert (%d) '%s'.\n", ret,
                                 gnutls_alert_get_name(ret));
                }

                if (gnutls_error_is_fatal(ret) != 0) {
                    gnutls_deinit(ctxt->session);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                                 "GnuTLS: Handshake Failed (%d) '%s'", ret,
                                 gnutls_strerror(ret));
                    ctxt->status = -1;
                    break;
                }
            }
            else {
                ctxt->status = 1;
                break;          /* all done with the handshake */
            }
        }
    }

    if (ctxt->status < 0) {
        return ap_pass_brigade(f->next, bb);
    }

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *bucket = APR_BRIGADE_FIRST(bb);
        if (APR_BUCKET_IS_EOS(bucket) || APR_BUCKET_IS_FLUSH(bucket)) {
            /** TODO: GnuTLS doesn't have a special flush method? **/
            if ((status = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
                return status;
            }
            break;
        }
        else if (AP_BUCKET_IS_EOC(bucket)) {
            gnutls_bye(ctxt->session, GNUTLS_SHUT_WR);

            if ((status = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
                return status;
            }
            break;
        }
        else {
            /* filter output */
            const char *data;
            apr_size_t len;

            status = apr_bucket_read(bucket, &data, &len, rblock);

            if (APR_STATUS_IS_EAGAIN(status)) {
                rblock = APR_BLOCK_READ;
                continue;       /* and try again with a blocking read. */
            }

            rblock = APR_NONBLOCK_READ;

            if (!APR_STATUS_IS_EOF(status) && (status != APR_SUCCESS)) {
                break;
            }

            ret = gnutls_record_send(ctxt->session, data, len);
            if (ret < 0) {
                /* error sending output */
            }
            else if ((apr_size_t) ret != len) {
                /* not all of the data was sent. */
                /* mod_ssl basicly errors out here.. this doesn't seem right? */
            }
            else {
                /* send complete */

            }

            apr_bucket_delete(bucket);

            if (status != APR_SUCCESS) {
                break;
            }

        }
    }

    return status;
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


ssize_t mod_gnutls_transport_read(gnutls_transport_ptr_t ptr,
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

ssize_t mod_gnutls_transport_write(gnutls_transport_ptr_t ptr,
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

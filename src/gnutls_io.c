/**
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
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

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

/**
 * Describe how the GnuTLS Filter system works here
 *  - Basicly the same as what mod_ssl does with OpenSSL.
 *
 */

#define HTTP_ON_HTTPS_PORT \
    "GET /" CRLF

#define HTTP_ON_HTTPS_PORT_BUCKET(alloc) \
    apr_bucket_immortal_create(HTTP_ON_HTTPS_PORT, \
                               sizeof(HTTP_ON_HTTPS_PORT) - 1, \
                               alloc)

static apr_status_t gnutls_io_filter_error(ap_filter_t * f,
        apr_bucket_brigade * bb,
        apr_status_t status) {
    mgs_handle_t *ctxt = (mgs_handle_t *) f->ctx;
    apr_bucket *bucket;

    switch (status) {
        case HTTP_BAD_REQUEST:
            /* log the situation */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                    f->c->base_server,
                    "GnuTLS handshake failed: HTTP spoken on HTTPS port; "
                    "trying to send HTML error page");

				    mgs_srvconf_rec *sc = (mgs_srvconf_rec *) ap_get_module_config(
																												f->c->base_server->module_config,
																												&gnutls_module
																											);
            ctxt->status = -1;
            sc->non_ssl_request = 1;

            /* fake the request line */
            bucket = HTTP_ON_HTTPS_PORT_BUCKET(f->c->bucket_alloc);
            break;

        default:
            return status;
    }

    APR_BRIGADE_INSERT_TAIL(bb, bucket);
    bucket = apr_bucket_eos_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, bucket);

    return APR_SUCCESS;
}

static int char_buffer_read(mgs_char_buffer_t * buffer, char *in, int inl) {
    if (!buffer->length) {
        return 0;
    }

    if (buffer->length > inl) {
        /* we have have enough to fill the caller's buffer */
        memmove(in, buffer->value, inl);
        buffer->value += inl;
        buffer->length -= inl;
    } else {
        /* swallow remainder of the buffer */
        memmove(in, buffer->value, buffer->length);
        inl = buffer->length;
        buffer->value = NULL;
        buffer->length = 0;
    }

    return inl;
}

static int char_buffer_write(mgs_char_buffer_t * buffer, char *in, int inl) {
    buffer->value = in;
    buffer->length = inl;
    return inl;
}

/**
 * From mod_ssl / ssl_engine_io.c
 * This function will read from a brigade and discard the read buckets as it
 * proceeds.  It will read at most *len bytes.
 */
static apr_status_t brigade_consume(apr_bucket_brigade * bb,
        apr_read_type_e block,
        char *c, apr_size_t * len) {
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
            consume =
                    (str_len + actual >
                    *len) ? *len - actual : str_len;

            memcpy(c, str, consume);

            c += consume;
            actual += consume;

            if (consume >= b->length) {
                /* This physical bucket was consumed */
                apr_bucket_delete(b);
            } else {
                /* Only part of this physical bucket was consumed */
                b->start += consume;
                b->length -= consume;
            }
        } else if (b->length == 0) {
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

static apr_status_t gnutls_io_input_read(mgs_handle_t * ctxt,
        char *buf, apr_size_t * len) {
    apr_size_t wanted = *len;
    apr_size_t bytes = 0;
    int rc;

    *len = 0;

    /* If we have something leftover from last time, try that first. */
    if ((bytes = char_buffer_read(&ctxt->input_cbuf, buf, wanted))) {
        *len = bytes;
        if (ctxt->input_mode == AP_MODE_SPECULATIVE) {
            /* We want to rollback this read. */
            if (ctxt->input_cbuf.length > 0) {
                ctxt->input_cbuf.value -= bytes;
                ctxt->input_cbuf.length += bytes;
            } else {
                char_buffer_write(&ctxt->input_cbuf, buf,
                        (int) bytes);
            }
            return APR_SUCCESS;
        }
        /* This could probably be *len == wanted, but be safe from stray
         * photons.
         */
        if (*len >= wanted) {
            return APR_SUCCESS;
        }
        if (ctxt->input_mode == AP_MODE_GETLINE) {
            if (memchr(buf, APR_ASCII_LF, *len)) {
                return APR_SUCCESS;
            }
        } else {
            /* Down to a nonblock pattern as we have some data already
             */
            ctxt->input_block = APR_NONBLOCK_READ;
        }
    }

    if (ctxt->session == NULL) {
        return APR_EGENERAL;
    }

    while (1) {

        rc = gnutls_record_recv(ctxt->session, buf + bytes,
                wanted - bytes);

        if (rc > 0) {
            *len += rc;
            if (ctxt->input_mode == AP_MODE_SPECULATIVE) {
                /* We want to rollback this read. */
                char_buffer_write(&ctxt->input_cbuf, buf,
                        rc);
            }
            return ctxt->input_rc;
        } else if (rc == 0) {
            /* If EAGAIN, we will loop given a blocking read,
             * otherwise consider ourselves at EOF.
             */
            if (APR_STATUS_IS_EAGAIN(ctxt->input_rc)
                    || APR_STATUS_IS_EINTR(ctxt->input_rc)) {
                /* Already read something, return APR_SUCCESS instead.
                 * On win32 in particular, but perhaps on other kernels,
                 * a blocking call isn't 'always' blocking.
                 */
                if (*len > 0) {
                    ctxt->input_rc = APR_SUCCESS;
                    break;
                }
                if (ctxt->input_block == APR_NONBLOCK_READ) {
                    break;
                }
            } else {
                if (*len > 0) {
                    ctxt->input_rc = APR_SUCCESS;
                } else {
                    ctxt->input_rc = APR_EOF;
                }
                break;
            }
        } else { /* (rc < 0) */

            if (rc == GNUTLS_E_REHANDSHAKE) {
                /* A client has asked for a new Hankshake. Currently, we don't do it */
                ap_log_error(APLOG_MARK, APLOG_INFO,
                        ctxt->input_rc,
                        ctxt->c->base_server,
                        "GnuTLS: Error reading data. Client Requested a New Handshake."
                        " (%d) '%s'", rc,
                        gnutls_strerror(rc));
            } else if (rc == GNUTLS_E_WARNING_ALERT_RECEIVED) {
                rc = gnutls_alert_get(ctxt->session);
                ap_log_error(APLOG_MARK, APLOG_INFO,
                        ctxt->input_rc,
                        ctxt->c->base_server,
                        "GnuTLS: Warning Alert From Client: "
                        " (%d) '%s'", rc,
                        gnutls_alert_get_name(rc));
            } else if (rc == GNUTLS_E_FATAL_ALERT_RECEIVED) {
                rc = gnutls_alert_get(ctxt->session);
                ap_log_error(APLOG_MARK, APLOG_INFO,
                        ctxt->input_rc,
                        ctxt->c->base_server,
                        "GnuTLS: Fatal Alert From Client: "
                        "(%d) '%s'", rc,
                        gnutls_alert_get_name(rc));
                ctxt->input_rc = APR_EGENERAL;
                break;
            } else {
                /* Some Other Error. Report it. Die. */
                if (gnutls_error_is_fatal(rc)) {
                    ap_log_error(APLOG_MARK,
                            APLOG_INFO,
                            ctxt->input_rc,
                            ctxt->c->base_server,
                            "GnuTLS: Error reading data. (%d) '%s'",
                            rc,
                            gnutls_strerror(rc));
                } else if (*len > 0) {
                    ctxt->input_rc = APR_SUCCESS;
                    break;
                }
            }

            if (ctxt->input_rc == APR_SUCCESS) {
                ctxt->input_rc = APR_EGENERAL;
            }
            break;
        }
    }
    return ctxt->input_rc;
}

static apr_status_t gnutls_io_input_getline(mgs_handle_t * ctxt,
        char *buf, apr_size_t * len) {
    const char *pos = NULL;
    apr_status_t status;
    apr_size_t tmplen = *len, buflen = *len, offset = 0;

    *len = 0;

    while (tmplen > 0) {
        status = gnutls_io_input_read(ctxt, buf + offset, &tmplen);

        if (status != APR_SUCCESS) {
            return status;
        }

        *len += tmplen;

        if ((pos = memchr(buf, APR_ASCII_LF, *len))) {
            break;
        }

        offset += tmplen;
        tmplen = buflen - offset;
    }

    if (pos) {
        char *value;
        int length;
        apr_size_t bytes = pos - buf;

        bytes += 1;
        value = buf + bytes;
        length = *len - bytes;

        char_buffer_write(&ctxt->input_cbuf, value, length);

        *len = bytes;
    }

    return APR_SUCCESS;
}

#define HANDSHAKE_MAX_TRIES 1024

static int gnutls_do_handshake(mgs_handle_t * ctxt) {
    int ret;
    int errcode;
    int maxtries = HANDSHAKE_MAX_TRIES;

    if (ctxt->status != 0 || ctxt->session == NULL) {
        return -1;
    }

tryagain:
    do {
        ret = gnutls_handshake(ctxt->session);
        maxtries--;
    } while ((ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN)
            && maxtries > 0);

    if (maxtries < 1) {
        ctxt->status = -1;
#if USING_2_1_RECENT
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, ctxt->c,
                "GnuTLS: Handshake Failed. Hit Maximum Attempts");
#else
        ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                ctxt->c->base_server,
                "GnuTLS: Handshake Failed. Hit Maximum Attempts");
#endif
        if (ctxt->session) {
            gnutls_alert_send(ctxt->session, GNUTLS_AL_FATAL,
                    gnutls_error_to_alert
                    (GNUTLS_E_INTERNAL_ERROR, NULL));
            gnutls_deinit(ctxt->session);
        }
        ctxt->session = NULL;
        return -1;
    }

    if (ret < 0) {
        if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
                || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
            errcode = gnutls_alert_get(ctxt->session);
            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                    ctxt->c->base_server,
                    "GnuTLS: Hanshake Alert (%d) '%s'.",
                    errcode,
                    gnutls_alert_get_name(errcode));
        }

        if (!gnutls_error_is_fatal(ret)) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                    ctxt->c->base_server,
                    "GnuTLS: Non-Fatal Handshake Error: (%d) '%s'",
                    ret, gnutls_strerror(ret));
            goto tryagain;
        }
#if USING_2_1_RECENT
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, ctxt->c,
                "GnuTLS: Handshake Failed (%d) '%s'", ret,
                gnutls_strerror(ret));
#else
        ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                ctxt->c->base_server,
                "GnuTLS: Handshake Failed (%d) '%s'", ret,
                gnutls_strerror(ret));
#endif
        ctxt->status = -1;
        if (ctxt->session) {
            gnutls_alert_send(ctxt->session, GNUTLS_AL_FATAL,
                    gnutls_error_to_alert(ret,
                    NULL));
            gnutls_deinit(ctxt->session);
        }
        ctxt->session = NULL;
        return ret;
    } else {
        /* all done with the handshake */
        ctxt->status = 1;
        /* If the session was resumed, we did not set the correct
         * server_rec in ctxt->sc.  Go Find it. (ick!)
         */
        if (gnutls_session_is_resumed(ctxt->session)) {
            mgs_srvconf_rec *sc;
            sc = mgs_find_sni_server(ctxt->session);
            if (sc) {
                ctxt->sc = sc;
            }
        }
        return 0;
    }
}

int mgs_rehandshake(mgs_handle_t * ctxt) {
    int rv;

    if (ctxt->session == NULL)
        return -1;

    rv = gnutls_rehandshake(ctxt->session);

    if (rv != 0) {
        /* the client did not want to rehandshake. goodbye */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                ctxt->c->base_server,
                "GnuTLS: Client Refused Rehandshake request.");
        return -1;
    }

    ctxt->status = 0;

    rv = gnutls_do_handshake(ctxt);

    return rv;
}

apr_status_t mgs_filter_input(ap_filter_t * f,
        apr_bucket_brigade * bb,
        ap_input_mode_t mode,
        apr_read_type_e block, apr_off_t readbytes) {
    apr_status_t status = APR_SUCCESS;
    mgs_handle_t *ctxt = (mgs_handle_t *) f->ctx;
    apr_size_t len = sizeof (ctxt->input_buffer);

    if (f->c->aborted) {
        apr_bucket *bucket =
                apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
        return APR_ECONNABORTED;
    }

    if (ctxt->status == 0) {
        gnutls_do_handshake(ctxt);
    }

    if (ctxt->status < 0) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* XXX: we don't currently support anything other than these modes. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE &&
            mode != AP_MODE_SPECULATIVE && mode != AP_MODE_INIT) {
        return APR_ENOTIMPL;
    }

    ctxt->input_mode = mode;
    ctxt->input_block = block;

    if (ctxt->input_mode == AP_MODE_READBYTES ||
            ctxt->input_mode == AP_MODE_SPECULATIVE) {
        /* Err. This is bad. readbytes *can* be a 64bit int! len.. is NOT */
        if (readbytes < len) {
            len = (apr_size_t) readbytes;
        }
        status =
                gnutls_io_input_read(ctxt, ctxt->input_buffer, &len);
    } else if (ctxt->input_mode == AP_MODE_GETLINE) {
        status =
                gnutls_io_input_getline(ctxt, ctxt->input_buffer,
                &len);
    } else {
        /* We have no idea what you are talking about, so return an error. */
        return APR_ENOTIMPL;
    }

    if (status != APR_SUCCESS) {
        return gnutls_io_filter_error(f, bb, status);
    }

    /* Create a transient bucket out of the decrypted data. */
    if (len > 0) {
        apr_bucket *bucket =
                apr_bucket_transient_create(ctxt->input_buffer, len,
                f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }

    return status;
}

static ssize_t write_flush(mgs_handle_t * ctxt) {
    apr_bucket *e;

    if (!(ctxt->output_blen || ctxt->output_length)) {
        ctxt->output_rc = APR_SUCCESS;
        return 1;
    }

    if (ctxt->output_blen) {
        e = apr_bucket_transient_create(ctxt->output_buffer,
                ctxt->output_blen,
                ctxt->output_bb->
                bucket_alloc);
        /* we filled this buffer first so add it to the
         * 		 * head of the brigade
         * 		 		 */
        APR_BRIGADE_INSERT_HEAD(ctxt->output_bb, e);
        ctxt->output_blen = 0;
    }

    ctxt->output_length = 0;
    e = apr_bucket_flush_create(ctxt->output_bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(ctxt->output_bb, e);

    ctxt->output_rc = ap_pass_brigade(ctxt->output_filter->next,
            ctxt->output_bb);
    /* clear the brigade to be ready for next time */
    apr_brigade_cleanup(ctxt->output_bb);

    return (ctxt->output_rc == APR_SUCCESS) ? 1 : -1;
}

apr_status_t mgs_filter_output(ap_filter_t * f, apr_bucket_brigade * bb) {
    apr_size_t ret;
    mgs_handle_t *ctxt = (mgs_handle_t *) f->ctx;
    apr_status_t status = APR_SUCCESS;
    apr_read_type_e rblock = APR_NONBLOCK_READ;

    if (f->c->aborted) {
        apr_brigade_cleanup(bb);
        return APR_ECONNABORTED;
    }

    if (ctxt->status == 0) {
        gnutls_do_handshake(ctxt);
    }

    if (ctxt->status < 0) {
        return ap_pass_brigade(f->next, bb);
    }

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *bucket = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_EOS(bucket)) {
            return ap_pass_brigade(f->next, bb);
        } else if (APR_BUCKET_IS_FLUSH(bucket)) {
            /* Try Flush */
            if (write_flush(ctxt) < 0) {
                /* Flush Error */
                return ctxt->output_rc;
            }
            /* cleanup! */
            apr_bucket_delete(bucket);
        } else if (AP_BUCKET_IS_EOC(bucket)) {
            /* End Of Connection */
            if (ctxt->session != NULL) {
                /* Try A Clean Shutdown */
                do {
                    ret = gnutls_bye(ctxt->session, GNUTLS_SHUT_WR);
                } while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
                /* De-Initialize Session */
                gnutls_deinit(ctxt->session);
                ctxt->session = NULL;
            }
            /* cleanup! */
            apr_bucket_delete(bucket);
            /* Pass next brigade! */
            return ap_pass_brigade(f->next, bb);
        } else {
            /* filter output */
            const char *data;
            apr_size_t len;

            status = apr_bucket_read(bucket, &data, &len, rblock);

            if (APR_STATUS_IS_EAGAIN(status)) {
                /* No data available so Flush! */
                if (write_flush(ctxt) < 0) {
                    return ctxt->output_rc;
                }
                /* Try again with a blocking read. */
                rblock = APR_BLOCK_READ;
                continue;
            }

            rblock = APR_NONBLOCK_READ;

            if (!APR_STATUS_IS_EOF(status)
                    && (status != APR_SUCCESS)) {
                return status;
            }

            if (len > 0) {

                if (ctxt->session == NULL) {
                    ret = GNUTLS_E_INVALID_REQUEST;
                } else {
                    do {
                        ret =
                                gnutls_record_send
                                (ctxt->session, data,
                                len);
                    } while (ret == GNUTLS_E_INTERRUPTED
                            || ret == GNUTLS_E_AGAIN);
                }

                if (ret < 0) {
                    /* error sending output */
                    ap_log_error(APLOG_MARK,
                            APLOG_INFO,
                            ctxt->output_rc,
                            ctxt->c->base_server,
                            "GnuTLS: Error writing data."
                            " (%d) '%s'",
                            (int) ret,
                            gnutls_strerror(ret));
                    if (ctxt->output_rc == APR_SUCCESS) {
                        ctxt->output_rc =
                                APR_EGENERAL;
                        return ctxt->output_rc;
                    }
                } else if (ret != len) {
                    /* Not able to send the entire bucket,
                       split it and send it again. */
                    apr_bucket_split(bucket, ret);
                }
            }

            apr_bucket_delete(bucket);
        }
    }

    return status;
}

ssize_t mgs_transport_read(gnutls_transport_ptr_t ptr,
        void *buffer, size_t len) {
    mgs_handle_t *ctxt = ptr;
    apr_status_t rc;
    apr_size_t in = len;
    apr_read_type_e block = ctxt->input_block;

    ctxt->input_rc = APR_SUCCESS;

    /* If Len = 0, we don't do anything. */
    if (!len || buffer == NULL) {
        return 0;
    }
    if (!ctxt->input_bb) {
        ctxt->input_rc = APR_EOF;
        return -1;
    }

    if (APR_BRIGADE_EMPTY(ctxt->input_bb)) {

        rc = ap_get_brigade(ctxt->input_filter->next,
                ctxt->input_bb, AP_MODE_READBYTES,
                ctxt->input_block, in);

        /* Not a problem, there was simply no data ready yet.
         */
        if (APR_STATUS_IS_EAGAIN(rc) || APR_STATUS_IS_EINTR(rc)
                || (rc == APR_SUCCESS
                && APR_BRIGADE_EMPTY(ctxt->input_bb))) {

            if (APR_STATUS_IS_EOF(ctxt->input_rc)) {
                return 0;
            } else {
                if (ctxt->session)
                    gnutls_transport_set_errno(ctxt->
                        session,
                        EINTR);
                return -1;
            }
        }


        if (rc != APR_SUCCESS) {
            /* Unexpected errors discard the brigade */
            apr_brigade_cleanup(ctxt->input_bb);
            ctxt->input_bb = NULL;
            return -1;
        }
    }

    ctxt->input_rc =
            brigade_consume(ctxt->input_bb, block, buffer, &len);

    if (ctxt->input_rc == APR_SUCCESS) {
        return (ssize_t) len;
    }

    if (APR_STATUS_IS_EAGAIN(ctxt->input_rc)
            || APR_STATUS_IS_EINTR(ctxt->input_rc)) {
        if (len == 0) {
            if (ctxt->session)
                gnutls_transport_set_errno(ctxt->session,
                    EINTR);
            return -1;
        }

        return (ssize_t) len;
    }

    /* Unexpected errors and APR_EOF clean out the brigade.
     * Subsequent calls will return APR_EOF.
     */
    apr_brigade_cleanup(ctxt->input_bb);
    ctxt->input_bb = NULL;

    if (APR_STATUS_IS_EOF(ctxt->input_rc) && len) {
        /* Provide the results of this read pass,
         * without resetting the BIO retry_read flag
         */
        return (ssize_t) len;
    }

    return -1;
}

ssize_t mgs_transport_write(gnutls_transport_ptr_t ptr,
        const void *buffer, size_t len) {
    mgs_handle_t *ctxt = ptr;

    /* pass along the encrypted data
     * need to flush since we're using SSL's malloc-ed buffer
     * which will be overwritten once we leave here
     */
    apr_bucket *bucket = apr_bucket_transient_create(buffer, len,
            ctxt->output_bb->
            bucket_alloc);
    ctxt->output_length += len;
    APR_BRIGADE_INSERT_TAIL(ctxt->output_bb, bucket);

    if (write_flush(ctxt) < 0) {
        return -1;
    }
    return len;
}

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

#include "mod_gnutls.h"

#include <apr_lib.h>
#include <apr_strings.h>
#include <byteswap.h>
#include <gnutls/gnutls.h>
#include <inttypes.h>

/** Defined in https://tools.ietf.org/html/rfc6066#section-1.1 */
#define EXT_ID_SERVER_NAME 0
/** "host_name" type as defined in
 * https://tools.ietf.org/html/rfc6066#section-3 */
#define SERVER_NAME_TYPE_DNS 0
/** size of type and length field for each ServerName as defined in
 * https://tools.ietf.org/html/rfc6066#section-3 */
#define SERVER_NAME_HDR_SIZE (sizeof(uint16_t) + sizeof(uint8_t))

static inline uint16_t read_uint16(const unsigned char *data)
{
    uint16_t u;
    memcpy(&u, data, sizeof(uint16_t));
#if APR_IS_BIGENDIAN == 0
    u = bswap_16(u);
#endif
    return u;
}

/**
 * APR port of GnuTLS' _gnutls_dnsname_is_valid() (from lib/str.h)
 */
static inline int is_valid_dnsname(const unsigned char *str, unsigned int size)
{
    for (unsigned int i = 0; i < size; i++)
    {
        if (!(apr_isalnum(str[i]) || str[i] == '-' || str[i] == '.'))
            return 0;
    }
    return 1;
}

/**
 * Callback for gnutls_ext_raw_parse(), called for each
 * extension. Check if the extension is a Server Name Indication,
 * parse if so. The SNI data structure is defined in [RFC 6066
 * Sec. 3](https://tools.ietf.org/html/rfc6066#section-3)
 */
int mgs_sni_ext_hook(void *ctx, unsigned tls_id,
                     const unsigned char *data, unsigned size)
{
    const char *name = NULL;

    gnutls_session_t session = (gnutls_session_t) ctx;
    mgs_handle_t *ctxt = (mgs_handle_t *) gnutls_session_get_ptr(session);

    if (tls_id == EXT_ID_SERVER_NAME)
    {
        /*
         * This is SNI extension data. GnuTLS does the following (see
         * _gnutls_server_name_recv_params() in lib/ext/server_name.c):
         *
         * Verify that total length lines up with received data size
         *
         * Iterate over type/size pairs, if type == 0 it's a DNS
         * name. Ignore any other type.
         *
         * Verify a DNS name using _gnutls_dnsname_is_valid() (from
         * lib/str.h)
         *
         * In case of any issue with sizes:
         * return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
         *
         * In case of invalid data:
         * return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
         */

        /* Read position for parsing */
        unsigned int pos = 0;

        /* Size of the ServerNameList (2 bytes) */
        if (size < sizeof(uint16_t))
            return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        uint16_t list_len = read_uint16(data);
        pos += sizeof(uint16_t);

        if (pos + list_len != size)
            return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;

        while (pos + SERVER_NAME_HDR_SIZE <= size)
        {
            /* NameType (one byte) */
            uint8_t type = *(data + pos);
            pos += sizeof(uint8_t);
            /* Size of the ServerName (2 bytes) */
            uint16_t name_len = read_uint16(data + pos);
            pos += sizeof(uint16_t);

            if (pos + name_len > size)
                return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;

            if (type == SERVER_NAME_TYPE_DNS)
            {
                if (!is_valid_dnsname(data + pos, name_len))
                    return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
                /* Without APR pools this would require a target
                 * buffer or malloc/free */
                name = apr_pstrndup(ctxt->c->pool,
                                    (const char *) data + pos,
                                    name_len);
                /* We don't handle any other ServerName types, ignore
                 * whatever follows */
                break;
            }
            pos += name_len;
        }
    }

    if (name != NULL)
    {
        /* Assign to session context */
        ctxt->sni_name = name;
    }
    return 0;
}

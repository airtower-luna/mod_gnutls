/**
 * Check if GnuTLS was compiled with OpenPGP support
 *
 * Copyright 2017 Fiona Klute
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You
 * may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include <gnutls/gnutls.h>
#include <gnutls/openpgp.h>

#include <stdio.h>

int main()
{
    gnutls_openpgp_crt_t cert;
    int ret = gnutls_openpgp_crt_init(&cert);
    if (ret == GNUTLS_E_UNIMPLEMENTED_FEATURE)
    {
        printf("OpenPGP support is disabled in libgnutls.\n");
        return 77;
    }
    if (ret != GNUTLS_E_SUCCESS)
    {
        fprintf(stderr, "Unexpected error in gnutls_openpgp_crt_init(): "
                "%s (%d)\n", gnutls_strerror(ret), ret);
        return 1;
    }
    gnutls_openpgp_crt_deinit(cert);
    return 0;
}

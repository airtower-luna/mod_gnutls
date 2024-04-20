/**
 * Helper functions for certificate handling in the mod_gnutls test suite
 *
 * Copyright 2016 Fiona Klute
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
#ifndef _MGS_CERT_HELPER_H_
#define _MGS_CERT_HELPER_H_

#include <gnutls/gnutls.h>



/**
 * Read the file "filename" into "cert", plus a NULL byte at the
 * end. "filename" may be NULL, in that case input is read from
 * stdin. The size field of data is set accordingly. The data field is
 * allocated to the needed size, the caller must free it when no
 * longer needed.
 *
 * Returns zero on success, or an error code (errno after the failed
 * operation).
 */
size_t read_cert(const char* filename, gnutls_datum_t* cert);

#endif /* _MGS_CERT_HELPER_H_ */

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
 * GnuTLS Session Cache using libmemcached
 *
 */
/*
#include "memcache.h"

int mod_gnutls_cache_init()
{
  return 0;
}
static int cache_store((void* baton, gnutls_datum_t key, gnutls_datum_t data)
{
    mc_set(struct memcache *mc,
           key->data, key->size,
           data->data, data->size, 
           3600, 0);
  return 0;
}

static int cache_fetch(void* baton, gnutls_datum_t key)
{
    mod_gnutls_handle_t *ctxt = baton;
  return 0;
}

static int cache_delete(void* baton, gnutls_datum_t key)
{
    mod_gnutls_handle_t *ctxt = baton;
  return 0;
}

int mod_gnutls_cache_session_init(mod_gnutls_handle_t *ctxt)
{
    gnutls_db_set_cache_expiration
    gnutls_db_set_retrieve_function(session, cache_fetch);
    gnutls_db_set_remove_function(session, cache_delete);
    gnutls_db_set_store_function(session, cache_store);
    gnutls_db_set_ptr(session, NULL);
  return 0;
}
*/

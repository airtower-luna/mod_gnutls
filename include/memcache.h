/* Copyright (c) 2004 Sean Chittenden <sean@chittenden.org>
 *
 * All rights reserved until such time as this code is released with
 * an official license.  Use of this code for commerical,
 * non-commercial, and personal purposes is encouraged.  Public forks
 * of this code is permitted so long as the fork and its decendents
 * use this copyright/license.  Use of this software in programs
 * released under the GPL programs is expressly prohibited by the
 * author (ie, BSD, closed source, or artistic license is okay, but
 * GPL is not). */

#ifndef MEMCACHE_H
#define MEMCACHE_H

#include <netdb.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Our initial read(2) buffer has to be long enough to read the
 * first line of the response.  ie:
 *
 * "VALUE #{'k' * 250} #{2 ** 15} #{2 ** 32}\r\n.length => 275
 *
 * However, since we want to avoid the number of system calls
 * necessary, include trailing part of the protocol in our estimate:
 *
 * "\r\nEND\r\n".length => 7
 *
 * Which yields a manditory limit of 282 bytes for a successful
 * response.  If we wish to try and get lucky with our first read(2)
 * call and be able to read(2) in small values without making a second
 * read(2) call, pad this number with a sufficiently large byte value.
 * If most of your keys are 512B, then a GET_INIT_BUF_SIZE of 794
 * would be prudent (512 + 282).
 *
 * The default value of 1024 means that values less than 724 bytes
 * will always be read(2) via the first read(2) call.  Increasing this
 * value to large values is not beneficial.  If a second read(2) call
 * is necessary, the read(2) will be made with a sufficiently large
 * buffer already allocated. */
#define GET_INIT_BUF_SIZE ((size_t)1024)

/* Enables extra protocol checking.  It's not strickly necesary if the
 * server's sending the right data.  This should be on by default,
 * but, for those that don't want every check done to make sure things
 * are right, undef this.  99% of the universe should leave this as
 * is.  If you think you're than 1% who doesn't need it, you're on
 * crack and should definately leave PEDANTIC on. %*/
#define PEDANTIC

#define MAX_KEY_LEN 250

#define HAVE_SELECT 1

#define USE_CRC32_HASH 1
/* #define USE_ELF_HASH 1 */
/* #define USE_PERL_HASH 1 */

/* Various values for _flags */
#define MC_RES_FREE_ON_DELETE		0x01
#define MC_RES_NO_FREE_ON_DELETE	0x02
#define MC_RES_FOUND			0x04
struct memcache_res {
  const char *key;	/* key */
  size_t len;		/* length of key */
  u_int32_t hash;	/* hash of the key */
  void *val;		/* the value */
  size_t bytes;		/* length of val */

  /* If size is zero (default), the memory for val is automatically
   * allocated using mcMalloc(3).  If size is zero, _flags has its
   * MC_RES_FREE_ON_DELETE bit set.
   *
   * If size is non-zero, libmemcache(3) assumes that the caller has
   * set val to an available portion of memory that is size bytes
   * long.  libmemcache(3) will only populate val with as many bytes
   * as are specified by size (ie, it will trim the value in order to
   * fit into val). If size is non-zero, _flags has its
   * MC_RES_NO_FREE_ON_DELETE bit set by default. */
  size_t size;
  TAILQ_ENTRY(memcache_res) entries;

  /* Note: this flags is very different than _flags. */
  u_int16_t flags;

  /* If _flags has 0x01 set, val will be free(3)'ed on when this
   * struct is cleaned up via mc_res_free() or the request is cleaned
   * up via mc_req_free().
   *
   * If _flags has is 0x02 set, val will not be free(3)'ed when this
   * response or its parent request are cleaned up.
   *
   * Note: Use mc_res_free_on_delete() to set the "free on delete"
   * bits. */
  char _flags;
};

struct memcache_req {
  TAILQ_HEAD(memcache_res_list, memcache_res) query;
  u_int16_t num_keys;
};

struct memcache_server {
  /* The hostname of the server. */
  char *hostname;

  /* Port number of the host we're connecting to. */
  char *port;

  /* The file descriptor for this server */
  int fd;

  /* The file descriptor flags */
  int flags;

  /* The timeout for this server */
  struct timeval tv;

  /* Is this particular server active or not?
   *
   * 'd' == Down	Last request was unsuccessful
   * 'n' == No host	The hostname doesn't exist
   * 't' == Try		Haven't connected to it yet, will attempt
   * 'u' == Up		Has been connected to successfully
   */
  char active;

  /* A cached copy of the looked up host. */
  struct addrinfo *hostinfo;

  /* The number of addresses in the cached copy.  If there is more
   * than one per DNS entry (discouraged), we establish a connection
   * to them all. */
  u_int32_t num_addrs;

#ifdef HAVE_SELECT
  /* Reduces the amount of user time required when reading data. */
  fd_set fds;
  struct timeval select_tv;
#endif

  /* Misc list bits */
  TAILQ_ENTRY(memcache_server) entries;
};


struct memcache_server_stats {
  pid_t pid;
  time_t uptime;
  time_t time;
  char *version;
  struct timeval rusage_user;
  struct timeval rusage_system;
  u_int32_t curr_items;
  u_int64_t total_items;
  u_int64_t bytes;
  u_int32_t curr_connections;
  u_int64_t total_connections;
  u_int32_t connection_structures;
  u_int64_t cmd_get;
  u_int64_t cmd_refresh;
  u_int64_t cmd_set;
  u_int64_t get_hits;
  u_int64_t get_misses;
  u_int64_t refresh_hits;
  u_int64_t refresh_misses;
  u_int64_t bytes_read;
  u_int64_t bytes_written;
  u_int64_t limit_maxbytes;
};


struct memcache {
  /* The default timeout for all servers */
  struct timeval tv;

  /* The default read(2) size when reading a response. */
  size_t read_size;

  /* The complete list of servers */
  TAILQ_HEAD(memcache_server_list, memcache_server) server_list;

  /* A buffer for data */
  char *buf;

  /* A cursor for where we are in the buffer */
  char *cur;

  /* A pointer to where data should be appended with future read(2)
   * calls. */
  char *read_cur;

  /* A pointer to the start of the current line in the buffer. */
  char *start;

  /* The allocated size of the buffer */
  size_t size;

  /* The number of servers in live_servers */
  u_int32_t num_live_servers;

  /* An array of usable memcache_servers */
  struct memcache_server **live_servers;
};


/* Adds a given key to the cache */
int			 mc_add(struct memcache *mc,
				const char *key, const size_t key_len,
				const void *val, const size_t bytes,
				const time_t expire, const u_int16_t flags);

/* Gets the value from memcache and allocates the data for the caller.
 * It is the caller's responsibility to free the returned value.
 * mc_get() is the preferred interface, however. */
void			*mc_aget(struct memcache *mc, const char *key, const size_t len);

/* Gets the value from memcache and allocates the data for the caller.
 * It is the caller's responsibility to free the returned value.
 * mc_refresh() is the preferred interface, however. */
void			*mc_arefresh(struct memcache *mc, const char *key, const size_t len);

/* Disconnects from a given server and marks it as down. */
void			 mc_deactivate_server(struct memcache *mc, struct memcache_server *ms);

/* Decrements a given key */
u_int32_t		 mc_decr(struct memcache *mc, const char *key, const size_t key_len, const u_int32_t val);

/* Deletes a given key */
int			 mc_delete(struct memcache *mc, const char *key, const size_t key_len, const time_t hold);

/* When given a hash value, this function returns the appropriate
 * server to connect to in order to find the key. */
struct memcache_server	*mc_find_server(struct memcache *mc, const u_int32_t hash);

/* Flushes all keys */
int			 mc_flush_all(struct memcache *mc, const char *key, const size_t key_len);

/* cleans up a memcache object. */
void			 mc_free(struct memcache *mc);

/* Tells the response object to free the allocated memory when it gets
 * cleaned up or to let the caller manage the memory. */
void			 mc_res_free_on_delete(struct memcache_res *res, int free_on_delete);

/* mc_get() is the preferred method of accessing memcache.  It
 * accepts multiple keys and lets a user (should they so choose)
 * perform memory caching to reduce the number of mcMalloc(3) calls
 * mades. */
void			 mc_get(struct memcache *mc, struct memcache_req *req);

/* Generates a hash value from a given key */
u_int32_t		 mc_hash_key(const char *key, const size_t len);

/* Increments a given key */
u_int32_t		 mc_incr(struct memcache *mc, const char *key, const size_t key_len, const u_int32_t val);

/* Allocates a new memcache object */
struct memcache	*mc_new(void);

/* mc_refresh() is the preferred method of accessing memcache.  It
 * accepts multiple keys and lets a user (should they so choose)
 * perform memory caching to reduce the number of mcMalloc(3) calls
 * mades.  mc_refresh() differs from mc_get() in that mc_refresh
 * updates the expiration time to be now + whatever the expiration for
 * the item was set to.  Sessions should use this as a way of noting
 * sessions expiring. */
void			 mc_refresh(struct memcache *mc, struct memcache_req *req);

/* Replaces a given key to the cache */
int			 mc_replace(struct memcache *mc,
				    const char *key, const size_t key_len,
				    const void *val, const size_t bytes,
				    const time_t expire, const u_int16_t flags);

/* Adds a key to a given request */
struct memcache_res	*mc_req_add(struct memcache_req *req, const char *key, size_t len);

/* Cleans up a given request and its subsequent responses.  If _flags
 * has the MC_RES_FREE_ON_DELETE bit set (default), it will clean up
 * the value too.  If _flags has MC_RES_NO_FREE_ON_DELETE set,
 * however, it is the caller's responsibility to free the value.  To
 * prevent double free(3) errors, if a value is free(3)'ed before
 * mc_req_free() is called, set val to NULL. */
void			 mc_req_free(struct memcache_req *req);

/* Allocates a new memcache request object. */
struct memcache_req	*mc_req_new(void);

/* Cleans up an individual response object.  Normally this is not
 * necessary as a call to mc_req_free() will clean up its response
 * objects. */
void			 mc_res_free(struct memcache_req *req, struct memcache_res *res);

/* Adds a server to the list of available servers.  By default,
 * servers are assumed to be available.  Return codes:
 *
 * 0:	success
 * -1:	Unable to allocate a new server instance
 * -2:	Unable to strdup hostname
 * -3:	Unable to strdup port
 * -4:	Unable to Unable to resolve the host, server deactivated, but added to list
 * -5:	Unable to realloc(3) the server list, server list unchanged */
int			 mc_server_add(struct memcache *mc, const char *hostname, const char *port);
int			 mc_server_add2(struct memcache *mc,
					const char *hostname, const size_t hostname_len,
					const char *port, const size_t port_len);

/* Cleans up a given stat's object */
void			 mc_server_stats_free(struct memcache_server_stats *s);

/* Gets a stats object from the given server.  It is the caller's
 * responsibility to cleanup the resulting object via
 * mc_server_stats_free(). */
struct memcache_server_stats	*mc_server_stats(struct memcache *mc, struct memcache_server *ms);

/* Sets a given key */
int			 mc_set(struct memcache *mc,
				const char *key, const size_t key_len,
				const void *val, const size_t bytes,
				const time_t expire, const u_int16_t flags);

/* Creates a stats object for all available servers and returns the
 * cumulative stats.  Per host-specific data is generally the same as
 * the last server querried. */
struct memcache_server_stats	*mc_stats(struct memcache *mc);

/* Sets the default timeout for new servers. */
void mc_timeout(struct memcache *mc, const int sec, const int usec);



/* BEGIN memory management API functions */

/* The memcache API allows callers to provide their own memory
 * allocation routines to aid in embedability with existing programs,
 * libraries, programming languages, and environments that have their
 * own memory handling routines.  This interface was inspired by
 * libxml. */
typedef void	 (*mcFreeFunc)(void *mem);
typedef void	*(*mcMallocFunc)(const size_t size);
typedef void	*(*mcReallocFunc)(void *mem, const size_t size);
typedef char	*(*mcStrdupFunc)(const char *str);

extern mcFreeFunc	mcFree;
extern mcMallocFunc	mcMalloc;
extern mcMallocFunc	mcMallocAtomic;
extern mcReallocFunc	mcRealloc;
extern mcStrdupFunc	mcStrdup;

int	mcMemSetup(mcFreeFunc freeFunc, mcMallocFunc mallocFunc,
		   mcReallocFunc reallocFunc, mcStrdupFunc strdupFunc);
int	mcMemGet(mcFreeFunc *freeFunc, mcMallocFunc *mallocFunc,
		 mcReallocFunc *reallocFunc, mcStrdupFunc *strdupFunc);
/* END memory management API functions */


/* APIs that should be implemented: */

/* Resets all hosts that are down to try */
void mc_server_reset_all_active(struct memcache *mc);

/* Resets a given host back to a try state */
void mc_server_reset_active(struct memcache *mc, const char *hostname, const int port);

/* Resets all dns entries */
void mc_server_reset_all_dns(struct memcache *mc);

/* Resets only one host's DNS cache */
void mc_server_reset_dns(struct memcache *mc, const char *hostname, const int port);

/* Disconnects from all memcache servers */
void mc_server_disconnect_all(struct memcache *mc);

/* Disconnects from one memcache server */
void mc_server_disconnect(struct memcache *mc, const char *hostname, const int port);

#ifdef TCP_NODELAY
/* Enable/disable TCP_NODELAY */
void mc_nodelay_enable(struct memcache *mc, const int enable);

/* Enable/disable TCP_NODELAY for a given server */
void mc_server_nodelay_enable(struct memcache_server *ms, const int enable);
#endif

/* Set the timeout on a per server basis */
void mc_server_timeout(struct memcache_server *ms, const int sec, const int usec);

/* Set the number of seconds you're willing to wait in total for a
 * response. ??? */

#ifdef __cplusplus
}
#endif

#endif

/**
 *  Copyright 2004-2005 Paul Querna
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

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <ctype.h>

static char *MGS_LUA_RRKEY = "request_rec";

static request_rec *mgs_lua_getrr(lua_State * lvm)
{
	request_rec *r;

	/* Push the request_rec off the registry, onto the stack. */
	lua_pushlightuserdata(lvm, MGS_LUA_RRKEY);
	lua_gettable(lvm, LUA_REGISTRYINDEX);
	r = lua_touserdata(lvm, -1);
	lua_pop(lvm, 1);
	return r;
}

static int get_request_table(lua_State * lvm, long offset)
{
	const char *key;
	request_rec *r;
	const char *value;
	apr_table_t *t;
	key = luaL_checkstring(lvm, 1);

	r = mgs_lua_getrr(lvm);

	t = *(apr_table_t **) ((char *) r + offset);

	value = apr_table_get(t, key);

	if (value) {
		lua_pushstring(lvm, value);
		return 1;
	} else {
		return 0;
	}
}

static int mgs_lua_getenv(lua_State * lvm)
{
	return get_request_table(lvm,
				 APR_OFFSETOF(request_rec,
					      subprocess_env));
}

static int mgs_lua_getheader(lua_State * lvm)
{
	return get_request_table(lvm,
				 APR_OFFSETOF(request_rec, headers_in));
}

static const luaL_reg mgs_lua_reg[] = {
	{"getenv", mgs_lua_getenv},
	{"header", mgs_lua_getheader},
	{NULL, NULL}
};

lua_State *get_luastate()
{
	lua_State *lvm = lua_open();
	luaopen_base(lvm);
	luaopen_io(lvm);
	luaopen_table(lvm);
	luaopen_string(lvm);
	luaopen_math(lvm);
	luaopen_loadlib(lvm);
	luaL_openlib(lvm, "ap", mgs_lua_reg, 0);

	return lvm;
}

int mgs_authz_lua(request_rec * r)
{
	int rv;
	lua_State *lvm;
	mgs_dirconf_rec *dc = ap_get_module_config(r->per_dir_config,
						   &gnutls_module);

	if (dc->lua_bytecode_len <= 0) {
		return 0;
	}

	lvm = get_luastate();
	lua_pushlightuserdata(lvm, MGS_LUA_RRKEY);
	lua_pushlightuserdata(lvm, r);
	lua_settable(lvm, LUA_REGISTRYINDEX);

	/* Push Bytecode onto the stack */
	rv = luaL_loadbuffer(lvm, dc->lua_bytecode, dc->lua_bytecode_len,
			     "gnutls-lua");

	if (rv != 0) {
		/* Get the Error message */
		const char *error = lua_tostring(lvm, -1);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			      "GnuTLS: Error Loading Lua Bytecode: %s",
			      error);
		lua_pop(lvm, 1);
		return -1;
	}

	rv = lua_pcall(lvm, 0, 1, 0);
	if (rv != 0) {
		/* Get the Error message */
		const char *error = lua_tostring(lvm, -1);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			      "GnuTLS: Error Running Lua: %s", error);
		lua_pop(lvm, 1);
		return -1;
	}

	rv = (int) lua_tonumber(lvm, -1);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		      "GnuTLS: (%d) Lua Return: %d",
		      dc->lua_bytecode_len, rv);
	lua_pop(lvm, 1);
	lua_close(lvm);
	return rv;
}

static apr_size_t config_getstr(ap_configfile_t * cfg, char *buf,
				size_t bufsiz)
{
	apr_size_t i = 0;

	if (cfg->getstr) {
		const char *res = (cfg->getstr) (buf, bufsiz, cfg->param);
		if (res) {
			i = strlen(buf);
			if (i && buf[i - 1] == '\n')
				++cfg->line_number;
		} else {
			buf[0] = '\0';
			i = 0;
		}
	} else {
		while (i < bufsiz) {
			int ch = (cfg->getch) (cfg->param);
			if (ch == EOF)
				break;
			buf[i++] = ch;
			if (ch == '\n') {
				++cfg->line_number;
				break;
			}
		}
	}
	return i;
}

struct cr_ctx {
	ap_configfile_t *cfp;
	size_t startline;
	char buf[HUGE_STRING_LEN];
};

static const char *LUACMD = "gnutlsrequire";
static const char *lf =
    "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
#define N_LF 32

static const char *direct_chunkreader(lua_State * lvm, void *udata,
				      size_t * plen)
{
	const char *p;
	struct cr_ctx *ctx = udata;

	if (ctx->startline) {
		*plen = ctx->startline > N_LF ? N_LF : ctx->startline;
		ctx->startline -= *plen;
		return lf;
	}
	*plen = config_getstr(ctx->cfp, ctx->buf, HUGE_STRING_LEN);

	for (p = ctx->buf; isspace(*p); ++p);
	if (p[0] == '<' && p[1] == '/') {
		int i = 0;
		while (i < strlen(LUACMD)) {
			if (tolower(p[i + 2]) != LUACMD[i])
				return ctx->buf;
			++i;
		}
		*plen = 0;
		return NULL;
	}
	return ctx->buf;
}

static int ldump_writer(lua_State * L, const void *b, size_t size, void *B)
{
	(void) L;
	luaL_addlstring((luaL_Buffer *) B, (const char *) b, size);
	return 1;
}

/* a bytecode buffer*/
typedef struct bcbuf_ctx {
	apr_size_t buflen;
	char *buf;
} bcbuf_ctx;

const char *mgs_set_require_section(cmd_parms * cmd, void *mconfig,
				    const char *arg)
{
	apr_size_t bytecode_len;
	const char *bytecode;
	bcbuf_ctx *bcbuf;
	luaL_Buffer b;
	ap_directive_t **current = mconfig;
	struct cr_ctx ctx[1];
	int result;
	const char *filename =
	    apr_psprintf(cmd->pool, "@%s", cmd->config_file->name);
	// get a word argument
	const char *word;
	apr_size_t wordlen;
	lua_State *lvm = get_luastate();

	word = ap_getword_conf(cmd->pool, &arg);
	wordlen = strlen(word);
	do {
		if (wordlen) {
			if (word[wordlen - 1] == '>') {
				--wordlen;
				break;
			}
			if (*arg == '>')
				break;
		}
		return apr_pstrcat(cmd->pool, "<", LUACMD,
				   "> takes exactly one argument", NULL);
	} while (0);

	ctx->cfp = cmd->config_file;
	ctx->startline = cmd->config_file->line_number;
	lua_settop(lvm, 0);
	result = lua_load(lvm, direct_chunkreader, ctx, filename);

	if (result != 0) {
		word =
		    apr_pstrcat(cmd->pool, "Lua Error:",
				lua_tostring(lvm, -1), NULL);
		lua_close(lvm);
		return word;
	} else {
		luaL_buffinit(lvm, &b);
		lua_dump(lvm, ldump_writer, &b);
		luaL_pushresult(&b);
		bytecode = lua_tostring(lvm, -1);
		bytecode_len = lua_strlen(lvm, -1);
	}

	/* Here, we have to replace our current config node for the next pass */
	if (!*current) {
		*current = apr_pcalloc(cmd->pool, sizeof(**current));
	}

	(*current)->filename = cmd->config_file->name;
	(*current)->line_num = ctx->startline;
	(*current)->directive =
	    apr_pstrdup(cmd->pool, "GnuTLSRequireByteCode");
	(*current)->args = NULL;

	bcbuf = apr_pcalloc(cmd->pool, sizeof(bcbuf));
	bcbuf->buflen = bytecode_len;
	bcbuf->buf = apr_pstrmemdup(cmd->pool, bytecode, bytecode_len);

	(*current)->data = bcbuf;
	lua_close(lvm);
	return NULL;
}

const char *mgs_set_require_bytecode(cmd_parms * cmd, void *mconfig,
				     const char *arg)
{
	bcbuf_ctx *bcbuf;
	ap_directive_t *directive = cmd->directive;
	mgs_dirconf_rec *dc = mconfig;

	bcbuf = directive->data;
	dc->lua_bytecode_len = bcbuf->buflen;
	dc->lua_bytecode =
	    apr_pstrmemdup(cmd->pool, bcbuf->buf, bcbuf->buflen);

	return NULL;
}

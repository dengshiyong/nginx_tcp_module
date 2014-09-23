#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include <ngx_tcp.h>


static void *ngx_tcp_core_create_main_conf(ngx_conf_t *cf) 
{
	ngx_tcp_core_main_conf_t  *cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_main_conf_t));
	if (cmcf == NULL) {
		return NULL;
	}

	if (ngx_array_init(&cmcf->servers, cf->pool, 4, sizeof(ngx_tcp_core_srv_conf_t *)) != NGX_OK) {
		return NULL;
	}

	if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_tcp_listen_t)) != NGX_OK) {
		return NULL;
	}

	if (ngx_array_init(&cmcf->virtual_servers, cf->pool, 4, sizeof(ngx_tcp_virtual_server_t)) != NGX_OK) {
		return NULL;
	}
	  
	return cmcf;
}

static void *ngx_tcp_core_create_srv_conf(ngx_conf_t *cf) 
{
	ngx_tcp_core_srv_conf_t  *cscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_srv_conf_t));
	if (cscf == NULL) {
		return NULL;
	}

	if (ngx_array_init(&cscf->server_names, cf->pool, 4, sizeof(ngx_tcp_server_name_t)) != NGX_OK) {
		return NULL;
	}

	if (ngx_array_init(&cscf->locations, cf->pool, 4, sizeof(ngx_tcp_core_loc_t)) != NGX_OK) {
		return NULL;
	}
	
	return cscf;
}


static char *ngx_tcp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) 
{
	return NGX_CONF_OK;
}



static char *ngx_tcp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_uint_t                  m;
	ngx_tcp_conf_ctx_t         *ctx, *tcp_ctx;

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	tcp_ctx = cf->ctx;
	ctx->main_conf = tcp_ctx->main_conf;

	/* the server{}'s srv_conf */
	ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
	if (ctx->srv_conf == NULL) {
		return NGX_CONF_ERROR;
	}

	for (m = 0; ngx_modules[m]; m++) {
		if (ngx_modules[m]->type != NGX_TCP_MODULE) {
			continue;
		}

		ngx_tcp_module_t *module = ngx_modules[m]->ctx;

		if (module->create_srv_conf) {
			void *mconf = module->create_srv_conf(cf);
			if (mconf == NULL) {
				return NGX_CONF_ERROR;
			}

			ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
		}
	}

	/* the server configuration context */
	ngx_tcp_core_srv_conf_t *cscf = ctx->srv_conf[ngx_tcp_core_module.ctx_index];
	cscf->ctx = ctx;

	ngx_tcp_core_main_conf_t *cmcf = ctx->main_conf[ngx_tcp_core_module.ctx_index];

	ngx_tcp_core_srv_conf_t *cscfp = ngx_array_push(&cmcf->servers);
	if (cscfp == NULL) {
		return NGX_CONF_ERROR;
	}

	cscfp = cscf;

	/* parse inside server{} */
	ngx_conf_t pcf = *cf;
	cf->ctx = ctx;
	cf->cmd_type = NGX_TCP_SRV_CONF;

	char *rv = ngx_conf_parse(cf, NULL);

	*cf = pcf;

	return rv;
}

static char *ngx_tcp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
	size_t                      len, off;
	in_port_t                   port;
	ngx_url_t                   u;
	ngx_uint_t                  i;
	struct sockaddr            *sa;
	ngx_tcp_listen_t           *ls;
	struct sockaddr_in         *sin;
	ngx_tcp_core_main_conf_t   *cmcf;

	ngx_str_t *value = cf->args->elts;

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = value[1];
	u.listen = 1;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in \"%V\" of the \"listen\" directive", u.err, &u.url);
		}

		return NGX_CONF_ERROR;
	}

	cmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_core_module);

	ls = cmcf->listen.elts;

	for (i = 0; i < cmcf->listen.nelts; i++) {

		sa = (struct sockaddr *) ls[i].sockaddr;

		if (sa->sa_family != u.family) {
			continue;
		}

		switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
		case AF_INET6:
			off = offsetof(struct sockaddr_in6, sin6_addr);
			len = 16;
			sin6 = (struct sockaddr_in6 *) sa;
			port = sin6->sin6_port;
			break;
#endif

		default: /* AF_INET */
			off = offsetof(struct sockaddr_in, sin_addr);
			len = 4;
			sin = (struct sockaddr_in *) sa;
			port = sin->sin_port;
			break;
		}

		if (ngx_memcmp(ls[i].sockaddr + off, u.sockaddr + off, len) != 0) {
			continue;
		}

		if (port != u.port) {
			continue;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate \"%V\" address and port pair", &u.url);
		return NGX_CONF_ERROR;
	}

	ls = ngx_array_push(&cmcf->listen);
	if (ls == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(ls, sizeof(ngx_tcp_listen_t));

	ngx_memcpy(ls->sockaddr, u.sockaddr, u.socklen);

	ls->socklen = u.socklen;
	ls->ctx = cf->ctx;
	ls->conf = conf;

	return NGX_CONF_OK;
}

static ngx_command_t  ngx_tcp_core_commands[] = {
	
	{ ngx_string("server"),
	  NGX_TCP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_MULTI|NGX_CONF_NOARGS,
	  ngx_tcp_core_server,
	  0,
	  0,
	  NULL },
	
	{ ngx_string("listen"),
	  NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
	  ngx_tcp_core_listen,
	  NGX_TCP_SRV_CONF_OFFSET,
	  0,
	  NULL },
	ngx_null_command
};


static ngx_tcp_module_t ngx_tcp_core_module_ctx = {
	ngx_tcp_core_create_main_conf,         /* create main configuration */
	NULL,                                  /* init main configuration */

	ngx_tcp_core_create_srv_conf,          /* create server configuration */
	ngx_tcp_core_merge_srv_conf            /* merge server configuration */
};


ngx_module_t  ngx_tcp_core_module = {
	NGX_MODULE_V1,
	&ngx_tcp_core_module_ctx,              /* module context */
	ngx_tcp_core_commands,                 /* module directives */
	NGX_TCP_MODULE,                        /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


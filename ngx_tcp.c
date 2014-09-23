#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "ngx_tcp.h"

#include <stdio.h>
#include <unistd.h>

ngx_uint_t  ngx_tcp_max_module;

static ngx_int_t ngx_tcp_add_addrs(ngx_conf_t *cf, ngx_tcp_port_t *mport, ngx_tcp_conf_addr_t *addr)
{
	u_char              *p;
	size_t               len;
	ngx_uint_t           i;
	ngx_tcp_in_addr_t   *addrs;
	struct sockaddr_in  *sin;
	u_char               buf[NGX_SOCKADDR_STRLEN];

	mport->addrs = ngx_pcalloc(cf->pool, mport->naddrs * sizeof(ngx_tcp_in_addr_t));
	if (mport->addrs == NULL) {
		return NGX_ERROR;
	}

	addrs = mport->addrs;

	for (i = 0; i < mport->naddrs; i++) {

		sin = (struct sockaddr_in *) addr[i].sockaddr;
		addrs[i].addr = sin->sin_addr.s_addr;


		len = ngx_sock_ntop(addr[i].sockaddr, addr[i].socklen, buf, NGX_SOCKADDR_STRLEN, 1);

		p = ngx_pnalloc(cf->pool, len);
		if (p == NULL) {
			return NGX_ERROR;
		}

		ngx_memcpy(p, buf, len);
	}

	return NGX_OK;
}


static ngx_int_t ngx_tcp_add_ports(ngx_conf_t *cf, ngx_array_t *ports, ngx_tcp_listen_t *listen)
{
	in_port_t              p;
	ngx_uint_t             i;
	struct sockaddr       *sa;
	struct sockaddr_in    *sin;
	ngx_tcp_conf_port_t   *port;
	ngx_tcp_conf_addr_t   *addr;

	sa = (struct sockaddr *) &listen->sockaddr;

	switch (sa->sa_family) {

	default: /* AF_INET */
		sin = (struct sockaddr_in *) sa;
		p = sin->sin_port;
		break;
	}

	port = ports->elts;
	for (i = 0; i < ports->nelts; i++) {
		if (p == port[i].port && sa->sa_family == port[i].family) {
			/* a port is already in the port list */
			port = &port[i];
			goto found;
		}
	}

	/* add a port to the port list */
	port = ngx_array_push(ports);
	if (port == NULL) {
		return NGX_ERROR;
	}

	port->family = sa->sa_family;
	port->port = p;

	if (ngx_array_init(&port->addrs, cf->temp_pool, 2, sizeof(ngx_tcp_conf_addr_t)) != NGX_OK)
	{
		return NGX_ERROR;
	}

found:
	addr = ngx_array_push(&port->addrs);
	if (addr == NULL) {
		return NGX_ERROR;
	}

	ngx_memzero(addr, sizeof(ngx_tcp_conf_addr_t));
	
	addr->sockaddr = (struct sockaddr *) &listen->sockaddr;
	addr->socklen = listen->socklen;
	addr->ctx = listen->ctx;

	return NGX_OK;
}


static char *ngx_tcp_optimize_servers(ngx_conf_t *cf, ngx_tcp_core_main_conf_t *cmcf, ngx_array_t *ports)
{
	ngx_uint_t             i, p, last;
	ngx_listening_t       *ls;


	ngx_tcp_conf_port_t *port = ports->elts;
	for (p = 0; p < ports->nelts; p++) {
		ngx_tcp_conf_addr_t   *addr = port[p].addrs.elts;
		last = port[p].addrs.nelts;
		
		i = 0;
		while (i < last) {
			ls = ngx_create_listening(cf, addr[i].sockaddr, addr[i].socklen);
			if (ls == NULL) {
				return NGX_CONF_ERROR;
			}

			ngx_tcp_port_t *mport = ngx_palloc(cf->pool, sizeof(ngx_tcp_port_t));
			if (mport == NULL) {
				return NGX_CONF_ERROR;
			}

			ls->addr_ntop = 1;
			ls->handler = ngx_tcp_init_connection;
			ls->pool_size = 256;
			
			/* TODO: err	or_log directive */
			ls->logp = &cf->cycle->new_log;
			ls->log.data = &ls->addr_text;
			ls->log.handler = ngx_accept_log_error;
	    
			ls->servers = mport;

			if (i == last - 1) {
				mport->naddrs = last;

			} else {
				mport->naddrs = 1;
				i = 0;
			}

			if (ngx_tcp_add_addrs(cf, mport, addr) != NGX_OK) {
				return NGX_CONF_ERROR;
			}
			
			addr++;
			last--;
		}
	}

	/*
	  ls = ngx_array_push(&cf->cycle->listening);  
	  if (ls == NULL) {  
	  return NULL;  
	  }  

	  ngx_memzero(ls, sizeof(ngx_listening_t));  
  
	  sa = ngx_palloc(cf->pool, socklen);  
	  if (sa == NULL) {  
	  return NULL;  
	  }  
  
	  ngx_memcpy(sa, sockaddr, socklen);  
  
	  ls->sockaddr = sa;  
	  ls->socklen = socklen;  
  
	  len = ngx_sock_ntop(sa, text, NGX_SOCKADDR_STRLEN, 1);  
	  ls->addr_text.len = len;ls->addr_text.data = ngx_pnalloc(cf->pool, len);  
	  if (ls->addr_text.data == NULL) {  
	  return NULL;  
	  }  
	  ngx_memcpy(ls->addr_text.data, text, len);
	*/
	
	return NGX_CONF_OK;
}


static char *ngx_tcp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char *rv = NULL;
	ngx_uint_t i = 0, mi = 0;
	ngx_conf_t pcf;
	ngx_array_t  ports;
	ngx_tcp_module_t *module = NULL;
	ngx_tcp_listen_t *listen = NULL;
	ngx_tcp_conf_ctx_t *ctx = NULL;
	ngx_tcp_core_main_conf_t *cmcf = NULL;

	/* the main tcp context */
	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}
	*(ngx_tcp_conf_ctx_t **) conf = ctx;

	/* count the number of the tcp modules and set up their indices */
	ngx_tcp_max_module = 0;
	for (i = 0; ngx_modules[i]; i++) {
		if (ngx_modules[i]->type != NGX_TCP_MODULE) {
			continue;
		}

		ngx_modules[i]->ctx_index = ngx_tcp_max_module++;
	}


	/* the tcp main_conf context */
	ctx->main_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
	if (ctx->main_conf == NULL) {
		return NGX_CONF_ERROR;
	}

	/*
	 * the tcp null srv_conf context, it is used to merge the server{}s' srv_conf's
	 */
	ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
	if (ctx->srv_conf == NULL) {
		return NGX_CONF_ERROR;
	}

	/*
	 * create the main_conf's, the null srv_conf's, and the null loc_conf's of the all tcp modules
	 */
	for (i = 0; ngx_modules[i]; i++) {
		if (ngx_modules[i]->type != NGX_TCP_MODULE) {
			continue;
		}

		module = ngx_modules[i]->ctx;
		mi = ngx_modules[i]->ctx_index;

		if (module->create_main_conf) {
			ctx->main_conf[mi] = module->create_main_conf(cf);
			if (ctx->main_conf[mi] == NULL) {
				return NGX_CONF_ERROR;
			}
		}

		if (module->create_srv_conf) {
			ctx->srv_conf[mi] = module->create_srv_conf(cf);
			if (ctx->srv_conf[mi] == NULL) {
				return NGX_CONF_ERROR;
			}
		}
	}

	/* parse inside the tcp{} block */
	pcf = *cf;
	cf->ctx = ctx;
	
	cf->module_type = NGX_TCP_MODULE;
	cf->cmd_type = NGX_TCP_MAIN_CONF;
	rv = ngx_conf_parse(cf, NULL);
	if (rv != NGX_CONF_OK) {
		*cf = pcf;
		return rv;
	}

	/* init tcp{} main_conf's, merge the server{}s' srv_conf's */
	cmcf = ctx->main_conf[ngx_tcp_core_module.ctx_index];
//	ngx_tcp_core_srv_conf_t **cscfp = NULL;	cscfp = cmcf->servers.elts;

	for (i = 0; ngx_modules[i]; i++) {
		if (ngx_modules[i]->type != NGX_TCP_MODULE) {
			continue;
		}

		module = ngx_modules[i]->ctx;
		mi = ngx_modules[i]->ctx_index;

		/* init tcp{} main_conf's */
		cf->ctx = ctx;
		if (module->init_main_conf) {
			rv = module->init_main_conf(cf, ctx->main_conf[mi]);
			if (rv != NGX_CONF_OK) {
				*cf = pcf;
				return rv;
			}
		}
	}

	
	*cf = pcf;

	if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_tcp_conf_port_t)) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	listen = cmcf->listen.elts;
	for (i = 0; i < cmcf->listen.nelts; i++) {
		if (ngx_tcp_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}
	
	return ngx_tcp_optimize_servers(cf, cmcf, &ports);
}


static ngx_command_t  ngx_tcp_commands[] = {
	{ ngx_string("tcp"),
	  NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
	  ngx_tcp_block,
	  0,
	  0,
	  NULL},
	
	ngx_null_command
};


static ngx_core_module_t  ngx_tcp_module_ctx = {
	ngx_string("tcp"),
	NULL,
	NULL
};


ngx_module_t  ngx_tcp_module = {
	NGX_MODULE_V1,
	&ngx_tcp_module_ctx,                   /* module context */
	ngx_tcp_commands,                      /* module directives */
	NGX_CORE_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


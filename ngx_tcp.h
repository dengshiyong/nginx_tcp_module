#ifndef _NGX_TCP_H_INCLUDED_
#define _NGX_TCP_H_INCLUDED_

#include "ngx_tcp_request.h"

typedef struct
{
	void **main_conf;
	void **srv_conf;
} ngx_tcp_conf_ctx_t;

typedef struct
{
	void *(*create_main_conf)(ngx_conf_t *cf);
	char *(*init_main_conf)(ngx_conf_t *cf, void *conf);

	void *(*create_srv_conf)(ngx_conf_t *cf);
	char *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_tcp_module_t;

typedef struct
{
	ngx_array_t              servers;
	ngx_array_t              listen;
	ngx_array_t              virtual_servers;
} ngx_tcp_core_main_conf_t;

typedef struct
{
	ngx_array_t              server_names;
	ngx_array_t              locations;
	ngx_tcp_conf_ctx_t      *ctx;
} ngx_tcp_core_srv_conf_t;

typedef struct
{
	u_char                  sockaddr[NGX_SOCKADDRLEN];
	socklen_t               socklen;
	
	ngx_tcp_conf_ctx_t     *ctx;
	
	ngx_tcp_core_srv_conf_t *conf;
} ngx_tcp_listen_t;

typedef struct
{
	int                      family;
	in_port_t                port;
	ngx_array_t              addrs;       /* array of ngx_tcp_conf_addr_t */
} ngx_tcp_conf_port_t;

typedef struct {
	struct sockaddr         *sockaddr;
	socklen_t                socklen;

	ngx_tcp_conf_ctx_t      *ctx;
	ngx_tcp_conf_ctx_t      *default_ctx;
} ngx_tcp_conf_addr_t;

typedef struct {
	ngx_tcp_conf_ctx_t      *ctx;
	ngx_tcp_conf_ctx_t      *default_ctx;
	ngx_str_t                addr_text;
#if (NGX_TCP_SSL)
	ngx_uint_t               ssl;    /* unsigned  ssl:1; */
#endif
} ngx_tcp_addr_conf_t;

typedef struct {
	in_addr_t                addr;
	ngx_tcp_addr_conf_t      conf;
} ngx_tcp_in_addr_t;

#if (NGX_HAVE_INET6)
typedef struct {
	struct in6_addr          addr6;
	ngx_tcp_addr_conf_t      conf;
} ngx_tcp_in6_addr_t;
#endif

typedef struct {
	void                    *addrs;
	ngx_uint_t               naddrs;
} ngx_tcp_port_t;

typedef struct {
	ngx_uint_t               hash;
	ngx_str_t                name;
	ngx_tcp_listen_t        *listen;
	ngx_tcp_conf_ctx_t      *ctx;
} ngx_tcp_virtual_server_t;

typedef struct {
	ngx_str_t                name;
} ngx_tcp_server_name_t;

typedef struct {
	ngx_str_t                name;
} ngx_tcp_core_loc_t;

typedef struct
{
	ngx_str_t           *client;
	ngx_connection_t    *connection;
	ngx_tcp_request_t   *reqctx;
} ngx_tcp_log_ctx_t;

#define NGX_TCP_MODULE 0x00504354     /* "TCP" */

#define NGX_TCP_MAIN_CONF         0x02000000
#define NGX_TCP_SRV_CONF          0x04000000

#define NGX_TCP_MAIN_CONF_OFFSET  offsetof(ngx_tcp_conf_ctx_t, main_conf)
#define NGX_TCP_SRV_CONF_OFFSET   offsetof(ngx_tcp_conf_ctx_t, srv_conf)

#define NGX_LOG_DEBUG_TCP         0x100

#define ngx_tcp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_tcp_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_tcp_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_tcp_get_module_main_conf(s, module) (s)->main_conf[module.ctx_index]
#define ngx_tcp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_tcp_conf_get_module_main_conf(cf, module) ((ngx_tcp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_tcp_conf_get_module_srv_conf(cf, module)  ((ngx_tcp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define ngx_tcp_cycle_get_module_main_conf(cycle, module)		\
	(cycle->conf_ctx[ngx_tcp_module.index] ? ((ngx_tcp_conf_ctx_t *)cycle->conf_ctx[ngx_tcp_module.index])->main_conf[module.ctx_index]: NULL)

extern ngx_uint_t    ngx_tcp_max_module;
extern ngx_module_t  ngx_tcp_core_module;

#endif /* _NGX_TCP_H_INCLUDED_ */

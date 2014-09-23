#ifndef _NGX_TCP_REQUEST_H_INCLUDED_
#define _NGX_TCP_REQUEST_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

typedef struct
{
	uint32_t sign;

	ngx_peer_connection_t            peer;
} ngx_tcp_upstream_t;


typedef struct {
	uint32_t                signature;         /* "TCP" */

	ngx_pool_t             *pool;

	ngx_connection_t       *connection;
	ngx_tcp_upstream_t     *upstream;

	ngx_str_t               out;
	ngx_buf_t              *buffer;

	void                  **ctx;
	void                  **main_conf;
	void                  **srv_conf;

	ngx_resolver_ctx_t     *resolver_ctx;

//	ngx_tcp_cleanup_t      *cleanup;

	time_t                  start_sec;
	ngx_msec_t              start_msec;

	off_t                   bytes_read;
	off_t                   bytes_write;

	unsigned                quit:1;
	ngx_str_t              *addr_text;
	ngx_str_t               host;

} ngx_tcp_request_t;


void ngx_tcp_init_connection(ngx_connection_t *c);
void ngx_tcp_close_connection(ngx_connection_t *c);
	
u_char *ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len);


#endif /* _NGX_TCP_REQUEST_H_INCLUDED_ */

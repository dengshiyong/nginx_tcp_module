#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "ngx_tcp.h"
#include "ngx_tcp_request.h"


void ngx_tcp_close_connection(ngx_connection_t *c)
{
	ngx_pool_t  *pool;

	ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0, "close tcp connection: %d", c->fd);

#if (NGX_TCP_SSL)
	if (c->ssl) {
		if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
			c->ssl->handler = ngx_tcp_close_connection;
			return;
		}
	}
#endif
	c->destroyed = 1;
	pool = c->pool;
	ngx_close_connection(c);
	ngx_destroy_pool(pool);
}

static void ngx_tcp_wait_request_handler(ngx_event_t *rev)
{
	size_t                     size = 1024;
	ssize_t                    n;
	ngx_connection_t          *c;
	ngx_buf_t                 *buf;
	
	c = rev->data;
	
	ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp wait request handler");
	
	/* 如果已经超时关闭连接
	if (rev->timedout) {
		ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
		ngx_tcp_close_connection(c);
		return;
	}

	if (c->close) {
		ngx_tcp_close_connection(c);
		return;
	}
	*/
//		ngx_tcp_request_t         *reqctx; reqctx = c->data;
	
	buf = c->buffer;
	if (buf == NULL) {
		buf = ngx_create_temp_buf(c->pool, size);
		if (buf == NULL) {
			ngx_tcp_close_connection(c);
			return;
		}

		c->buffer = buf;
	} else if (buf->start == NULL) {
		buf->start = ngx_palloc(c->pool, size);
		if (buf->start == NULL) {
			ngx_tcp_close_connection(c);
			return;
		}

		buf->pos = buf->start;
		buf->last = buf->start;
		buf->end = buf->last + size;
	}

	n = c->recv(c, buf->last, size);
	if (n == NGX_AGAIN) {
		if (!rev->timer_set) {
			ngx_add_timer(rev, c->listening->post_accept_timeout);
			ngx_reusable_connection(c, 1);
		}

		if (ngx_handle_read_event(rev, 0) != NGX_OK) {
			ngx_tcp_close_connection(c);
			return;
		}

		/*
		 * We are trying to not hold c->buffer's memory for an idle connection.
		 */

		if (ngx_pfree(c->pool, buf->start) == NGX_OK) {
			buf->start = NULL;
		}

		return;
	}

	if (n == NGX_ERROR) {
		ngx_tcp_close_connection(c);
		return;
	}

	if (n == 0) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0, "client closed connection");
		ngx_tcp_close_connection(c);
		return;
	}

	c->send(c, buf->last, n); // @@@@@@@@@@@@@@@
	
	buf->last += n;

	ngx_reusable_connection(c, 0);

	ngx_log_error(NGX_LOG_ERR, c->log, 0, "recv: %s", buf->start);
	
	return;
}


static void ngx_tcp_empty_handler(ngx_event_t *wev)
{
	ngx_log_debug0(NGX_LOG_DEBUG_TCP, wev->log, 0, "tcp empty handler");
	
	return;
}


void ngx_tcp_init_connection(ngx_connection_t *c)
{
	ngx_uint_t            i;
	struct sockaddr      *sa;
	struct sockaddr_in   *sin;
	ngx_tcp_request_t    *reqctx;
	ngx_tcp_log_ctx_t    *logctx;
	ngx_tcp_in_addr_t    *addr;
	ngx_tcp_addr_conf_t  *addr_conf;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6  *sin6;
	ngx_tcp_in6_addr_t   *addr6;
#endif

	/* find the server configuration for the address:port */
	/* AF_INET only */
	ngx_tcp_port_t *port = c->listening->servers;
	if (port->naddrs > 1) {
		/*
		 * There are several addresses on this port and one of them is the "*:port" wildcard
		 * so getsockname() is needed to determine the server address.
		 *
		 * AcceptEx() already gave this address.
		 */
		if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
			ngx_tcp_close_connection(c);
			return;
		}

		sa = c->local_sockaddr;

		switch (sa->sa_family) {
#if (NGX_HAVE_INET6)
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *) sa;
			addr6 = port->addrs;

			/* the last address is "*" */
			for (i = 0; i < port->naddrs - 1; i++) {
				if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
					break;
				}
			}

			addr_conf = &addr6[i].conf;
			break;
#endif

		default: /* AF_INET */
			sin = (struct sockaddr_in *) sa;
			addr = port->addrs;

			/* the last address is "*" */
			for (i = 0; i < port->naddrs - 1; i++) {
				if (addr[i].addr == sin->sin_addr.s_addr) {
					break;
				}
			}

			addr_conf = &addr[i].conf;
			break;
		}

	} else {
		switch (c->local_sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
		case AF_INET6:
			addr6 = port->addrs;
			addr_conf = &addr6[0].conf;
			break;
#endif
		default: /* AF_INET */
			addr = port->addrs;
			addr_conf = &addr[0].conf;
			break;
		}
	}

	reqctx = ngx_pcalloc(c->pool, sizeof(ngx_tcp_request_t));
	if (reqctx == NULL) {
		ngx_tcp_close_connection(c);
		return;
	}
/*
  这里配置没有初始化...
  if (addr_conf->default_ctx) {
  reqctx->main_conf = addr_conf->default_ctx->main_conf;
  reqctx->srv_conf = addr_conf->default_ctx->srv_conf;
  } else {
  reqctx->main_conf = addr_conf->ctx->main_conf;
  reqctx->srv_conf = addr_conf->ctx->srv_conf;
  }
*/
	reqctx->addr_text = &addr_conf->addr_text;

	c->data = reqctx;
	reqctx->connection = c;

	ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V", c->number, &c->addr_text, reqctx->addr_text);

	logctx = ngx_palloc(c->pool, sizeof(ngx_tcp_log_ctx_t));
	if (logctx == NULL) {
		ngx_tcp_close_connection(c);
		return;
	}

	logctx->client = &c->addr_text;
	logctx->connection = c;
	logctx->reqctx = reqctx;

	c->log->connection = c->number;
	c->log->handler = ngx_tcp_log_error;
	c->log->data = logctx;
	c->log->action = "nginx tcp module init connection";

	c->log_error = NGX_ERROR_INFO;

	ngx_event_t *rev = c->read; // 当前连接的读事件
	rev->handler = ngx_tcp_wait_request_handler; // 设置当前连接的读事件处理函数
	c->write->handler = ngx_tcp_empty_handler; // 写事件不做处理
	
#if (NGX_TCP_SSL)
	{
		ngx_tcp_ssl_srv_conf_t  *sscf;

		sscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_ssl_module);
		if (sscf->enable || addr_conf->ssl) {
		    
			if (c->ssl == NULL) {
				c->log->action = "SSL handshaking";
		
				if (addr_conf->ssl && sscf->ssl.ctx == NULL) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0, "no \"ssl_certificate\" is defined in server listening on SSL port");
					ngx_tcp_close_connection(c);
					return;
				}
		
				ngx_tcp_ssl_init_connection(&sscf->ssl, c);
				return;
			}
		}
	}
#endif

	if (rev->ready) {
		/* the deferred accept(), rtsig, aio, iocp */
		if (ngx_use_accept_mutex) {
			ngx_post_event(rev, &ngx_posted_events);
			return;
		}

		rev->handler(rev);
		return;
	}

	ngx_add_timer(rev, c->listening->post_accept_timeout);
	ngx_reusable_connection(c, 1);

	// 将读事件添加到事件驱动模块中
	if (ngx_handle_read_event(rev, 0) != NGX_OK) {
		ngx_tcp_close_connection(c);
		return;
	}
}

u_char *ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
	u_char              *p;
	ngx_tcp_request_t   *reqctx;
	ngx_tcp_log_ctx_t   *logctx;
	
	p = buf;

	if (log->action) {
		p = ngx_snprintf(p, len + (buf - p), " while %s", log->action);
	}
	
	logctx = log->data;
	p = ngx_snprintf(p, len + (buf - p), ", client: %V", logctx->client);
	
	reqctx = logctx->reqctx;
	if (reqctx == NULL) {
		return p;
	}
	
	p = ngx_snprintf(p, len + (buf - p), ", server: %V", reqctx->addr_text);
	
	if (reqctx->upstream) {
		if (reqctx->upstream->peer.connection) {
			p = ngx_snprintf(p, len + (buf - p), ", upstream: %V", reqctx->upstream->peer.name);
		}
	}
	
	return p;
}



#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


static void ngx_tcp_upstream_init_session(ngx_tcp_session_t *r);
static void ngx_tcp_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_tcp_upstream_rd_check_broken_connection(ngx_tcp_session_t *r);
static void ngx_tcp_upstream_wr_check_broken_connection(ngx_tcp_session_t *r);
static void ngx_tcp_upstream_check_broken_connection(ngx_tcp_session_t *r,
    ngx_event_t *ev);
static void ngx_tcp_upstream_connect(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u);
static ngx_int_t ngx_tcp_upstream_reinit(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u);
static void ngx_tcp_upstream_send_session(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u);
static void ngx_tcp_upstream_send_session_handler(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u);
static ngx_int_t ngx_tcp_upstream_test_connect(ngx_connection_t *c);
static void ngx_tcp_upstream_dummy_handler(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u);
static void ngx_tcp_upstream_next(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u, ngx_uint_t ft_type);
static void ngx_tcp_upstream_cleanup(void *data);
static void ngx_tcp_upstream_finalize_session(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u, ngx_int_t rc);

static char *ngx_tcp_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);
static char *ngx_tcp_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_tcp_upstream_create_main_conf(ngx_conf_t *cf);
static char *ngx_tcp_upstream_init_main_conf(ngx_conf_t *cf, void *conf);


ngx_tcp_upstream_header_t  ngx_tcp_upstream_headers_in[] = {
    { ngx_null_string, NULL, 0, NULL, 0, 0 }
};


static ngx_command_t  ngx_tcp_upstream_commands[] = {

    { ngx_string("upstream"),
      NGX_TCP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_tcp_upstream,
      0,
      0,
      NULL },

    { ngx_string("server"),
      NGX_TCP_UPS_CONF|NGX_CONF_1MORE,
      ngx_tcp_upstream_server,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_upstream_module_ctx = {
    NULL,
    NULL,       /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_tcp_upstream_create_main_conf,    /* create main configuration */
    ngx_tcp_upstream_init_main_conf,      /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_tcp_upstream_module = {
    NGX_MODULE_V1,
    &ngx_tcp_upstream_module_ctx,         /* module context */
    ngx_tcp_upstream_commands,            /* module directives */
    NGX_TCP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_tcp_upstream_create(ngx_tcp_session_t *r)
{
    ngx_tcp_upstream_t  *u;

    u = r->upstream;

    if (u && u->cleanup) {
        r->main->count++;
        ngx_tcp_upstream_cleanup(r);
    }

    u = ngx_pcalloc(r->pool, sizeof(ngx_tcp_upstream_t));
    if (u == NULL) {
        return NGX_ERROR;
    }

    r->upstream = u;

    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    u->peer.lock = &r->connection->lock;
#endif

    u->headers_in.content_length_n = -1;

    return NGX_OK;
}


void
ngx_tcp_upstream_init(ngx_tcp_session_t *r)
{
    ngx_connection_t     *c;

    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp init upstream, client timer: %d", c->read->timer_set);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
                == NGX_ERROR)
            {
                ngx_tcp_finalize_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    ngx_tcp_upstream_init_session(r);
}


static void
ngx_tcp_upstream_init_session(ngx_tcp_session_t *r)
{
    ngx_str_t                      *host;
    ngx_uint_t                      i;
    ngx_resolver_ctx_t             *ctx, temp;
    ngx_tcp_cleanup_t             *cln;
    ngx_tcp_upstream_t            *u;
    ngx_tcp_core_loc_conf_t       *clcf;
    ngx_tcp_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_tcp_upstream_main_conf_t  *umcf;

    if (r->aio) {
        return;
    }

    u = r->upstream;

    u->store = (u->conf->store || u->conf->store_lengths);

    if (!u->store && !u->conf->ignore_client_abort) {
        r->read_event_handler = ngx_tcp_upstream_rd_check_broken_connection;
        r->write_event_handler = ngx_tcp_upstream_wr_check_broken_connection;
    }


    if (u->create_session(r) != NGX_OK) {
        ngx_tcp_finalize_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.local = u->conf->local;

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);

    u->output.alignment = clcf->directio_alignment;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;
    u->output.output_filter = ngx_chain_writer;
    u->output.filter_ctx = &u->writer;

    u->writer.pool = r->pool;

    if (r->upstream_states == NULL) {

        r->upstream_states = ngx_array_create(r->pool, 1,
                                            sizeof(ngx_tcp_upstream_state_t));
        if (r->upstream_states == NULL) {
            ngx_tcp_finalize_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {

        u->state = ngx_array_push(r->upstream_states);
        if (u->state == NULL) {
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memzero(u->state, sizeof(ngx_tcp_upstream_state_t));
    }

    //cln = ngx_tcp_cleanup_add(r, 0);
    //TODO: must modify it!
    cln = NULL;
    if (cln == NULL) {
        ngx_tcp_finalize_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = ngx_tcp_upstream_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;

    if (u->resolved == NULL) {

        uscf = u->conf->upstream;

    } else {

        if (u->resolved->sockaddr) {

            if (ngx_tcp_upstream_create_round_robin_peer(r, u->resolved)
                != NGX_OK)
            {
                ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
                return;
            }

            ngx_tcp_upstream_connect(r, u);

            return;
        }

        host = &u->resolved->host;

        umcf = ngx_tcp_get_module_main_conf(r, ngx_tcp_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_memcmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->port == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no port in upstream \"%V\"", host);
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        ctx = ngx_resolve_start(clcf->resolver, &temp);
        if (ctx == NULL) {
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no resolver defined to resolve %V", host);

            ngx_tcp_upstream_finalize_session(r, u, NGX_TCP_BAD_GATEWAY);
            return;
        }

        ctx->name = *host;
        ctx->type = NGX_RESOLVE_A;
        ctx->handler = ngx_tcp_upstream_resolve_handler;
        ctx->data = r;
        ctx->timeout = clcf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf->peer.init(r, uscf) != NGX_OK) {
        ngx_tcp_upstream_finalize_session(r, u,
                                           NGX_TCP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_tcp_upstream_connect(r, u);
}


static void
ngx_tcp_upstream_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_tcp_session_t            *r;
    ngx_tcp_upstream_t           *u;
    ngx_tcp_upstream_resolved_t  *ur;

    r = ctx->data;

    u = r->upstream;
    ur = u->resolved;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_tcp_upstream_finalize_session(r, u, NGX_TCP_BAD_GATEWAY);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
    in_addr_t   addr;
    ngx_uint_t  i;

    for (i = 0; i < ctx->naddrs; i++) {
        addr = ntohl(ur->addrs[i]);

        ngx_log_debug4(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                       "name was resolved to %ud.%ud.%ud.%ud",
                       (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                       (addr >> 8) & 0xff, addr & 0xff);
    }
    }
#endif

    if (ngx_tcp_upstream_create_round_robin_peer(r, ur) != NGX_OK) {
        ngx_tcp_upstream_finalize_session(r, u,
                                           NGX_TCP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    ngx_tcp_upstream_connect(r, u);
}


static void
ngx_tcp_upstream_handler(ngx_event_t *ev)
{
    ngx_connection_t     *c;
    ngx_tcp_session_t   *r;
    ngx_tcp_log_ctx_t   *ctx;
    ngx_tcp_upstream_t  *u;

    c = ev->data;
    r = c->data;

    u = r->upstream;
    c = r->connection;

    ctx = c->log->data;
    ctx->current_session = r;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp upstream request: \"%V?%V\"", &r->uri, &r->args);

    if (ev->write) {
        u->write_event_handler(r, u);

    } else {
        u->read_event_handler(r, u);
    }
}


static void
ngx_tcp_upstream_rd_check_broken_connection(ngx_tcp_session_t *r)
{
    ngx_tcp_upstream_check_broken_connection(r, r->connection->read);
}


static void
ngx_tcp_upstream_wr_check_broken_connection(ngx_tcp_session_t *r)
{
    ngx_tcp_upstream_check_broken_connection(r, r->connection->write);
}


static void
ngx_tcp_upstream_check_broken_connection(ngx_tcp_session_t *r,
    ngx_event_t *ev)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_int_t            event;
    ngx_connection_t     *c;
    ngx_tcp_upstream_t  *u;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "tcp upstream check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;
    u = r->upstream;

    if (c->error) {
        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

            if (ngx_del_event(ev, event, 0) != NGX_OK) {
                ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        if (!u->cacheable) {
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_CLIENT_CLOSED_SESSION);
        }

        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client prematurely closed "
                          "connection, so upstream connection is closed too");
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, ev->log, err,
                   "tcp upstream recv(): %d", n);

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

        event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

        if (ngx_del_event(ev, event, 0) != NGX_OK) {
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (!u->cacheable && u->peer.connection) {
        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "client prematurely closed connection, "
                      "so upstream connection is closed too");
        ngx_tcp_upstream_finalize_session(r, u,
                                           NGX_TCP_CLIENT_CLOSED_SESSION);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    if (u->peer.connection == NULL) {
        ngx_tcp_upstream_finalize_session(r, u,
                                           NGX_TCP_CLIENT_CLOSED_SESSION);
    }
}


static void
ngx_tcp_upstream_connect(ngx_tcp_session_t *r, ngx_tcp_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_time_t        *tp;
    ngx_connection_t  *c;

    r->connection->log->action = "connecting to upstream";

    r->connection->single_connection = 0;

    if (u->state && u->state->response_sec) {
        tp = ngx_timeofday();
        u->state->response_sec = tp->sec - u->state->response_sec;
        u->state->response_msec = tp->msec - u->state->response_msec;
    }

    u->state = ngx_array_push(r->upstream_states);
    if (u->state == NULL) {
        ngx_tcp_upstream_finalize_session(r, u,
                                           NGX_TCP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_tcp_upstream_state_t));

    tp = ngx_timeofday();
    u->state->response_sec = tp->sec;
    u->state->response_msec = tp->msec;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp upstream connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_tcp_upstream_finalize_session(r, u,
                                           NGX_TCP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no live upstreams");
        ngx_tcp_upstream_next(r, u, NGX_TCP_UPSTREAM_FT_NOLIVE);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_tcp_upstream_next(r, u, NGX_TCP_UPSTREAM_FT_ERROR);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN */

    c = u->peer.connection;

    c->data = r;

    c->write->handler = ngx_tcp_upstream_handler;
    c->read->handler = ngx_tcp_upstream_handler;

    u->write_event_handler = ngx_tcp_upstream_send_session_handler;

    c->sendfile &= r->connection->sendfile;
    u->output.sendfile = c->sendfile;

    if (c->pool == NULL) {

        /* we need separate pool here to be able to cache SSL connections */

        c->pool = ngx_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    /* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit = 0;

    if (u->request_sent) {
        if (ngx_tcp_upstream_reinit(r, u) != NGX_OK) {
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    u->request_sent = 0;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

    ngx_tcp_upstream_send_session(r, u);
}



static ngx_int_t
ngx_tcp_upstream_reinit(ngx_tcp_session_t *r, ngx_tcp_upstream_t *u)
{
    ngx_chain_t  *cl;

    if (u->reinit_session(r) != NGX_OK) {
        return NGX_ERROR;
    }

    u->keepalive = 0;

    u->headers_in.content_length_n = -1;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* reinit the request chain */

    for (cl = u->request_bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->start;
        cl->buf->file_pos = 0;
    }

    u->output.buf = NULL;
    u->output.in = NULL;
    u->output.busy = NULL;

    /* reinit u->buffer */

    u->buffer.pos = u->buffer.start;

    u->buffer.last = u->buffer.pos;

    return NGX_OK;
}


static void
ngx_tcp_upstream_send_session(ngx_tcp_session_t *r, ngx_tcp_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp upstream send request");

    if (!u->request_sent && ngx_tcp_upstream_test_connect(c) != NGX_OK) {
        ngx_tcp_upstream_next(r, u, NGX_TCP_UPSTREAM_FT_ERROR);
        return;
    }

    c->log->action = "sending request to upstream";

    rc = ngx_output_chain(&u->output, u->request_sent ? NULL : u->request_bufs);

    u->request_sent = 1;

    if (rc == NGX_ERROR) {
        ngx_tcp_upstream_next(r, u, NGX_TCP_UPSTREAM_FT_ERROR);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->send_timeout);

        if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) {
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    /* rc == NGX_OK */

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                          ngx_tcp_push_n " failed");
            ngx_tcp_upstream_finalize_session(r, u,
                                               NGX_TCP_INTERNAL_SERVER_ERROR);
            return;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }

    ngx_add_timer(c->read, u->conf->read_timeout);

#if 1
    if (c->read->ready) {

        /* post aio operation */

        /*
         * TODO comment
         * although we can post aio operation just in the end
         * of ngx_tcp_upstream_connect() CHECK IT !!!
         * it's better to do here because we postpone header buffer allocation
         */

        return;
    }
#endif

    u->write_event_handler = ngx_tcp_upstream_dummy_handler;

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_tcp_upstream_finalize_session(r, u,
                                           NGX_TCP_INTERNAL_SERVER_ERROR);
        return;
    }
}


static void
ngx_tcp_upstream_send_session_handler(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u)
{
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp upstream send request handler");

    if (c->write->timedout) {
        ngx_tcp_upstream_next(r, u, NGX_TCP_UPSTREAM_FT_TIMEOUT);
        return;
    }


    if (u->header_sent) {
        u->write_event_handler = ngx_tcp_upstream_dummy_handler;

        (void) ngx_handle_write_event(c->write, 0);

        return;
    }

    ngx_tcp_upstream_send_session(r, u);
}


static ngx_int_t
ngx_tcp_upstream_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, c->write->kq_errno,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_tcp_upstream_dummy_handler(ngx_tcp_session_t *r, ngx_tcp_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp upstream dummy handler");
}


static void
ngx_tcp_upstream_next(ngx_tcp_session_t *r, ngx_tcp_upstream_t *u,
    ngx_uint_t ft_type)
{
    ngx_uint_t  status, state;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp next upstream, %xi", ft_type);

#if 0
    ngx_tcp_busy_unlock(u->conf->busy_lock, &u->busy_lock);
#endif

    if (ft_type == NGX_TCP_UPSTREAM_FT_TCP_404) {
        state = NGX_PEER_NEXT;
    } else {
        state = NGX_PEER_FAILED;
    }

    if (ft_type != NGX_TCP_UPSTREAM_FT_NOLIVE) {
        u->peer.free(&u->peer, u->peer.data, state);
    }

    if (ft_type == NGX_TCP_UPSTREAM_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (u->peer.cached && ft_type == NGX_TCP_UPSTREAM_FT_ERROR) {
        status = 0;

        /* TODO: inform balancer instead */

        u->peer.tries++;

    } else {
        switch(ft_type) {

        case NGX_TCP_UPSTREAM_FT_TIMEOUT:
            status = NGX_TCP_GATEWAY_TIME_OUT;
            break;

        case NGX_TCP_UPSTREAM_FT_TCP_500:
            status = NGX_TCP_INTERNAL_SERVER_ERROR;
            break;

        case NGX_TCP_UPSTREAM_FT_TCP_404:
            status = NGX_TCP_NOT_FOUND;
            break;

        /*
         * NGX_TCP_UPSTREAM_FT_BUSY_LOCK and NGX_TCP_UPSTREAM_FT_MAX_WAITING
         * never reach here
         */

        default:
            status = NGX_TCP_BAD_GATEWAY;
        }
    }

    if (r->connection->error) {
        ngx_tcp_upstream_finalize_session(r, u,
                                           NGX_TCP_CLIENT_CLOSED_SESSION);
        return;
    }

    if (status) {
        u->state->status = status;

        if (u->peer.tries == 0 || !(u->conf->next_upstream & ft_type)) {


            ngx_tcp_upstream_finalize_session(r, u, status);
            return;
        }
    }

    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                       "close tcp upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
        }

        ngx_close_connection(u->peer.connection);
        u->peer.connection = NULL;
    }

#if 0
    if (u->conf->busy_lock && !u->busy_locked) {
        ngx_tcp_upstream_busy_lock(p);
        return;
    }
#endif

    ngx_tcp_upstream_connect(r, u);
}


static void
ngx_tcp_upstream_cleanup(void *data)
{
    ngx_tcp_session_t *r = data;

    ngx_tcp_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "cleanup tcp upstream request: \"%V\"", &r->uri);

    u = r->upstream;

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    ngx_tcp_upstream_finalize_session(r, u, NGX_DONE);
}


static void
ngx_tcp_upstream_finalize_session(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u, ngx_int_t rc)
{
    ngx_time_t  *tp;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "finalize tcp upstream request: %i", rc);

    if (u->cleanup) {
        *u->cleanup = NULL;
        u->cleanup = NULL;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->state && u->state->response_sec) {
        tp = ngx_timeofday();
        u->state->response_sec = tp->sec - u->state->response_sec;
        u->state->response_msec = tp->msec - u->state->response_msec;

        if (u->pipe) {
            u->state->response_length = u->pipe->read_length;
        }
    }

    u->finalize_session(r, rc);

    if (u->peer.free) {
        u->peer.free(&u->peer, u->peer.data, 0);
    }

    if (u->peer.connection) {

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                       "close tcp upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
        }

        ngx_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->pipe && u->pipe->temp_file) {
        ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                       "tcp upstream temp fd: %d",
                       u->pipe->temp_file->file.fd);
    }

    if (u->store && u->pipe && u->pipe->temp_file
        && u->pipe->temp_file->file.fd != NGX_INVALID_FILE)
    {
        if (ngx_delete_file(u->pipe->temp_file->file.name.data)
            == NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_delete_file_n " \"%s\" failed",
                          u->pipe->temp_file->file.name.data);
        }
    }


    if (u->header_sent
        && rc != NGX_TCP_SESSION_TIME_OUT
        && (rc == NGX_ERROR || rc >= NGX_TCP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    if (rc == NGX_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";
/*
    if (rc == 0
       )
    {
        rc = ngx_tcp_send_special(r, NGX_TCP_LAST);
    }
*/
    ngx_tcp_finalize_session(r, rc);
}

static char *
ngx_tcp_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                          *rv;
    void                          *mconf;
    ngx_str_t                     *value;
    ngx_url_t                      u;
    ngx_uint_t                     m;
    ngx_conf_t                     pcf;
    ngx_tcp_module_t             *module;
    ngx_tcp_conf_ctx_t           *ctx, *tcp_ctx;
    ngx_tcp_upstream_srv_conf_t  *uscf;

    ngx_memzero(&u, sizeof(ngx_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;

    uscf = ngx_tcp_upstream_add(cf, &u, NGX_TCP_UPSTREAM_CREATE
                                         |NGX_TCP_UPSTREAM_WEIGHT
                                         |NGX_TCP_UPSTREAM_MAX_FAILS
                                         |NGX_TCP_UPSTREAM_FAIL_TIMEOUT
                                         |NGX_TCP_UPSTREAM_DOWN
                                         |NGX_TCP_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return NGX_CONF_ERROR;
    }


    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    tcp_ctx = cf->ctx;
    ctx->main_conf = tcp_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->srv_conf[ngx_tcp_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;


    /* the upstream{}'s loc_conf */

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->loc_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }


    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_TCP_UPS_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (uscf->servers == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return NGX_CONF_ERROR;
    }

    return rv;
}


static char *
ngx_tcp_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_upstream_srv_conf_t  *uscf = conf;

    time_t                       fail_timeout;
    ngx_str_t                   *value, s;
    ngx_url_t                    u;
    ngx_int_t                    weight, max_fails;
    ngx_uint_t                   i;
    ngx_tcp_upstream_server_t  *us;

    if (uscf->servers == NULL) {
        uscf->servers = ngx_array_create(cf->pool, 4,
                                         sizeof(ngx_tcp_upstream_server_t));
        if (uscf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    us = ngx_array_push(uscf->servers);
    if (us == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(us, sizeof(ngx_tcp_upstream_server_t));

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 80;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    weight = 1;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_WEIGHT)) {
                goto invalid;
            }

            weight = ngx_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NGX_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_MAX_FAILS)) {
                goto invalid;
            }

            max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_FAIL_TIMEOUT)) {
                goto invalid;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = ngx_parse_time(&s, 1);

            if (fail_timeout == (time_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "backup", 6) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_BACKUP)) {
                goto invalid;
            }

            us->backup = 1;

            continue;
        }

        if (ngx_strncmp(value[i].data, "down", 4) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_DOWN)) {
                goto invalid;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


ngx_tcp_upstream_srv_conf_t *
ngx_tcp_upstream_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags)
{
    ngx_uint_t                      i;
    ngx_tcp_upstream_server_t     *us;
    ngx_tcp_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_tcp_upstream_main_conf_t  *umcf;

    if (!(flags & NGX_TCP_UPSTREAM_CREATE)) {

        if (ngx_parse_url(cf->pool, u) != NGX_OK) {
            if (u->err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || ngx_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & NGX_TCP_UPSTREAM_CREATE)
             && (uscfp[i]->flags & NGX_TCP_UPSTREAM_CREATE))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & NGX_TCP_UPSTREAM_CREATE) && u->port) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & NGX_TCP_UPSTREAM_CREATE) && uscfp[i]->port) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

        if (uscfp[i]->port != u->port) {
            continue;
        }

        if (uscfp[i]->default_port && u->default_port
            && uscfp[i]->default_port != u->default_port)
        {
            continue;
        }

        if (flags & NGX_TCP_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
        }

        return uscfp[i];
    }

    uscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->default_port = u->default_port;

    if (u->naddrs == 1) {
        uscf->servers = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_tcp_upstream_server_t));
        if (uscf->servers == NULL) {
            return NULL;
        }

        us = ngx_array_push(uscf->servers);
        if (us == NULL) {
            return NULL;
        }

        ngx_memzero(us, sizeof(ngx_tcp_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    uscfp = ngx_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


char *
ngx_tcp_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    ngx_int_t     rc;
    ngx_str_t    *value;
    ngx_addr_t  **paddr;

    paddr = (ngx_addr_t **) (p + cmd->offset);

    *paddr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
    if (*paddr == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    rc = ngx_parse_addr(cf->pool, *paddr, value[1].data, value[1].len);

    switch (rc) {
    case NGX_OK:
        (*paddr)->name = value[1];
        return NGX_CONF_OK;

    case NGX_DECLINED:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid address \"%V\"", &value[1]);
        /* fall through */

    default:
        return NGX_CONF_ERROR;
    }
}


char *
ngx_tcp_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    ngx_str_t                   *value;
    ngx_array_t                **a;
    ngx_tcp_upstream_param_t   *param;

    a = (ngx_array_t **) (p + cmd->offset);

    if (*a == NULL) {
        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_tcp_upstream_param_t));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    param = ngx_array_push(*a);
    if (param == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    param->key = value[1];
    param->value = value[2];
    param->skip_empty = 0;

    if (cf->args->nelts == 4) {
        if (ngx_strcmp(value[3].data, "if_not_empty") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return NGX_CONF_ERROR;
        }

        param->skip_empty = 1;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_tcp_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_tcp_upstream_conf_t *conf, ngx_tcp_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash)
{
    ngx_str_t       *h;
    ngx_uint_t       i, j;
    ngx_array_t      hide_headers;
    ngx_hash_key_t  *hk;

    if (conf->hide_headers == NGX_CONF_UNSET_PTR
        && conf->pass_headers == NGX_CONF_UNSET_PTR)
    {
        conf->hide_headers = prev->hide_headers;
        conf->pass_headers = prev->pass_headers;

        conf->hide_headers_hash = prev->hide_headers_hash;

        if (conf->hide_headers_hash.buckets
           )
        {
            return NGX_OK;
        }

    } else {
        if (conf->hide_headers == NGX_CONF_UNSET_PTR) {
            conf->hide_headers = prev->hide_headers;
        }

        if (conf->pass_headers == NGX_CONF_UNSET_PTR) {
            conf->pass_headers = prev->pass_headers;
        }
    }

    if (ngx_array_init(&hide_headers, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (h = default_hide_headers; h->len; h++) {
        hk = ngx_array_push(&hide_headers);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = *h;
        hk->key_hash = ngx_hash_key_lc(h->data, h->len);
        hk->value = (void *) 1;
    }

    if (conf->hide_headers != NGX_CONF_UNSET_PTR) {

        h = conf->hide_headers->elts;

        for (i = 0; i < conf->hide_headers->nelts; i++) {

            hk = hide_headers.elts;

            for (j = 0; j < hide_headers.nelts; j++) {
                if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    goto exist;
                }
            }

            hk = ngx_array_push(&hide_headers);
            if (hk == NULL) {
                return NGX_ERROR;
            }

            hk->key = h[i];
            hk->key_hash = ngx_hash_key_lc(h[i].data, h[i].len);
            hk->value = (void *) 1;

        exist:

            continue;
        }
    }

    if (conf->pass_headers != NGX_CONF_UNSET_PTR) {

        h = conf->pass_headers->elts;
        hk = hide_headers.elts;

        for (i = 0; i < conf->pass_headers->nelts; i++) {
            for (j = 0; j < hide_headers.nelts; j++) {

                if (hk[j].key.data == NULL) {
                    continue;
                }

                if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    hk[j].key.data = NULL;
                    break;
                }
            }
        }
    }

    hash->hash = &conf->hide_headers_hash;
    hash->key = ngx_hash_key_lc;
    hash->pool = cf->pool;
    hash->temp_pool = NULL;

    return ngx_hash_init(hash, hide_headers.elts, hide_headers.nelts);
}


static void *
ngx_tcp_upstream_create_main_conf(ngx_conf_t *cf)
{
    ngx_tcp_upstream_main_conf_t  *umcf;

    umcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(ngx_tcp_upstream_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
ngx_tcp_upstream_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_tcp_upstream_main_conf_t  *umcf = conf;

    ngx_uint_t                      i;
    ngx_array_t                     headers_in;
    ngx_hash_key_t                 *hk;
    ngx_hash_init_t                 hash;
    ngx_tcp_upstream_init_pt       init;
    ngx_tcp_upstream_header_t     *header;
    ngx_tcp_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream ? uscfp[i]->peer.init_upstream:
                                            ngx_tcp_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }


    /* upstream_headers_in_hash */

    if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (header = ngx_tcp_upstream_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_CONF_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &umcf->headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "upstream_headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


static void ngx_tcp_init_session(ngx_event_t *ev);
static void ngx_tcp_process_session_line(ngx_event_t *rev);

static void ngx_tcp_session_handler(ngx_event_t *ev);
static void ngx_tcp_terminate_session(ngx_tcp_session_t *r, ngx_int_t rc);
static void ngx_tcp_terminate_handler(ngx_tcp_session_t *r);
static void ngx_tcp_finalize_connection(ngx_tcp_session_t *r);
//static ngx_int_t ngx_tcp_set_write_handler(ngx_tcp_session_t *r);
//static void ngx_tcp_writer(ngx_tcp_session_t *r);
//static void ngx_tcp_session_finalizer(ngx_tcp_session_t *r);

static void ngx_tcp_set_keepalive(ngx_tcp_session_t *r);
static void ngx_tcp_keepalive_handler(ngx_event_t *ev);
static void ngx_tcp_close_session(ngx_tcp_session_t *r, ngx_int_t error);
static void ngx_tcp_free_session(ngx_tcp_session_t *r, ngx_int_t error);
static void ngx_tcp_log_session(ngx_tcp_session_t *r);
static void ngx_tcp_close_connection(ngx_connection_t *c);

static u_char *ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len);
static u_char *ngx_tcp_log_error_handler(ngx_tcp_session_t *r,
    ngx_tcp_session_t *sr, u_char *buf, size_t len);


void
ngx_tcp_init_connection(ngx_connection_t *c)
{
    ngx_event_t         *rev;
    ngx_tcp_log_ctx_t  *ctx;

    ctx = ngx_palloc(c->pool, sizeof(ngx_tcp_log_ctx_t));
    if (ctx == NULL) {
        ngx_tcp_close_connection(c);
        return;
    }

    ctx->connection = c;
    ctx->session = NULL;
    ctx->current_session = NULL;

    c->log->connection = c->number;
    c->log->handler = ngx_tcp_log_error;
    c->log->data = ctx;
    c->log->action = "reading client session line";

    c->log_error = NGX_ERROR_INFO;

    rev = c->read;
    rev->handler = ngx_tcp_init_session;
    c->write->handler = ngx_tcp_empty_handler;

    if (rev->ready) {
        /* the deferred accept(), rtsig, aio, iocp */

        if (ngx_use_accept_mutex) {
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        ngx_tcp_init_session(rev);
        return;
    }

    //it will check the timer, if timeout
    ngx_add_timer(rev, c->listening->post_accept_timeout);

    //read data to epoll
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_close_connection(c);
        return;
    }
}


static void
ngx_tcp_init_session(ngx_event_t *rev)
{
    ngx_time_t                 *tp;
    ngx_uint_t                  i;
    ngx_connection_t           *c;
    ngx_tcp_session_t         *s;
    struct sockaddr_in         *sin;
    ngx_tcp_port_t            *port;
    ngx_tcp_in_addr_t         *addr;
    ngx_tcp_log_ctx_t         *ctx;
    ngx_tcp_addr_conf_t       *addr_conf;
    ngx_tcp_connection_t      *tc;
    ngx_tcp_core_srv_conf_t   *cscf;
    ngx_tcp_core_loc_conf_t   *clcf;
   // ngx_tcp_core_main_conf_t  *cmcf;

    c = rev->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "rev client timed out");

        ngx_tcp_close_connection(c);
        return;
    }

    c->sessions++;

    tc = c->data;

    if (tc == NULL) {
        tc = ngx_pcalloc(c->pool, sizeof(ngx_tcp_connection_t));
        if (tc == NULL) {
            ngx_tcp_close_connection(c);
            return;
        }
    }

    s = tc->session;

    if (s) {
        ngx_memzero(s, sizeof(ngx_tcp_session_t));
    } else {
        s = ngx_pcalloc(c->pool, sizeof(ngx_tcp_session_t));
        if (s == NULL) {
            ngx_tcp_close_connection(c);
            return;
        }

        tc->session = s;
    }

    c->data = s;
    s->tcp_connection = tc;

    c->sent = 0;
    s->signature = NGX_TCP_MODULE;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    s->connection = c;

    if (port->naddrs > 1) {

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in ngx_tcp_server_addr()
         * is required to determine a server address
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_tcp_close_connection(c);
            return;
        }

        switch (c->local_sockaddr->sa_family) {


        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;

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

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s->virtual_names = addr_conf->virtual_names;

    /* the default server configuration for the address:port */
    cscf = addr_conf->default_server;

    s->main_conf = cscf->ctx->main_conf;
    s->srv_conf = cscf->ctx->srv_conf;
    s->loc_conf = cscf->ctx->loc_conf;

    rev->handler = ngx_tcp_process_session_line;
    s->read_event_handler = ngx_tcp_block_reading;

    clcf = ngx_tcp_get_module_loc_conf(s, ngx_tcp_core_module);
    c->log->file = clcf->error_log->file;
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
        c->log->log_level = clcf->error_log->log_level;
    }

    if (c->buffer == NULL) {
        c->buffer = ngx_create_temp_buf(c->pool,
                                        cscf->client_header_buffer_size);
        if (c->buffer == NULL) {
            ngx_tcp_close_connection(c);
            return;
        }
    }

    /*
    if (r->header_in == NULL) {
        r->header_in = c->buffer;
    }
    */

    s->pool = ngx_create_pool(cscf->session_pool_size, c->log);
    if (s->pool == NULL) {
        ngx_tcp_close_connection(c);
        return;
    }


    s->ctx = ngx_pcalloc(s->pool, sizeof(void *) * ngx_tcp_max_module);
    if (s->ctx == NULL) {
        ngx_destroy_pool(s->pool);
        ngx_tcp_close_connection(c);
        return;
    }

 //   ngx_tcp_core_main_conf_t  *cmcf;
 //   cmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_core_module);

    c->single_connection = 1;
    c->destroyed = 0;

    s->main = s;
    s->count = 1;

    tp = ngx_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;

    s->tcp_state = NGX_TCP_READING_SESSION_STATE;

    ctx = c->log->data;
    ctx->session = s;
    ctx->current_session = s;
    s->log_handler = ngx_tcp_log_error_handler;

    rev->handler(rev);
}

static void
ngx_tcp_process_session_line(ngx_event_t *rev)
{
    return;
}
/*
static void
ngx_tcp_process_session(ngx_tcp_session_t *r)
{
    ngx_connection_t  *c;

    c = r->connection;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    r->stat_reading = 0;
    (void) ngx_atomic_fetch_add(ngx_stat_writing, 1);
    r->stat_writing = 1;
#endif

    c->read->handler = ngx_tcp_session_handler;
    c->write->handler = ngx_tcp_session_handler;
    r->read_event_handler = ngx_tcp_block_reading;

    ngx_tcp_handler(r);

    ngx_tcp_run_posted_sessions(c);
}
*/

static void
ngx_tcp_session_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_tcp_session_t  *r;
    ngx_tcp_log_ctx_t  *ctx;

    c = ev->data;
    r = c->data;

    ctx = c->log->data;
    ctx->current_session = r;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp run session: \"%V?%V\"", &r->uri, &r->args);

    if (ev->write) {
        r->write_event_handler(r);

    } else {
        r->read_event_handler(r);
    }

    ngx_tcp_run_posted_sessions(c);
}


void
ngx_tcp_run_posted_sessions(ngx_connection_t *c)
{
    /*ngx_tcp_session_t         *r;
    ngx_tcp_log_ctx_t         *ctx;
    ngx_tcp_posted_session_t  *pr;

    for ( ;; ) {

        if (c->destroyed) {
            return;
        }

        r = c->data;
        pr = r->main->posted_sessions;

        if (pr == NULL) {
            return;
        }

        r->main->posted_sessions = pr->next;

        r = pr->session;

        ctx = c->log->data;
        ctx->current_session = r;

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
                       "tcp posted session: \"%V?%V\"", &r->uri, &r->args);

        r->write_event_handler(r);
    }*/
    return ;
}

/*
ngx_int_t
ngx_tcp_post_session(ngx_tcp_session_t *r, ngx_tcp_posted_session_t *pr)
{
    
    ngx_tcp_posted_session_t  **p;

    if (pr == NULL) {
        pr = ngx_palloc(r->pool, sizeof(ngx_tcp_posted_session_t));
        if (pr == NULL) {
            return NGX_ERROR;
        }
    }

    pr->session = r;
    pr->next = NULL;

    for (p = &r->main->posted_sessions; *p; p = &(*p)->next) { }

    *p = pr;
    return NGX_OK;
}
*/

void
ngx_tcp_finalize_session(ngx_tcp_session_t *r, ngx_int_t rc)
{
    ngx_connection_t          *c;
    //ngx_tcp_session_t        *pr;
    //ngx_tcp_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug5(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp finalize session: %d, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == c->data, r->main->count);

    if (rc == NGX_DONE) {
        ngx_tcp_finalize_connection(r);
        return;
    }

    if (rc == NGX_OK) {
        c->error = 1;
    }
/*
    if (rc == NGX_DECLINED) {
        r->write_event_handler = ngx_tcp_core_run_phases;
        ngx_tcp_core_run_phases(r);
        return;
    }
*/
    if (rc == NGX_ERROR
        || rc == NGX_TCP_SESSION_TIME_OUT
        || rc == NGX_TCP_CLIENT_CLOSED_SESSION
        || c->error)
    {
       /* if (ngx_tcp_post_action(r) == NGX_OK) {
            return;
        }
        if (r->main->blocked) {
            r->write_event_handler = ngx_tcp_session_finalizer;
        }
        */
        ngx_tcp_terminate_session(r, rc);
        return;
    }

    if (rc >= NGX_TCP_SPECIAL_RESPONSE
        || rc == NGX_TCP_CREATED
        || rc == NGX_TCP_NO_CONTENT)
    {
        if (rc == NGX_TCP_CLOSE) {
            ngx_tcp_terminate_session(r, rc);
            return;
        }

        if (r == r->main) {
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            if (c->write->timer_set) {
                ngx_del_timer(c->write);
            }
        }

        c->read->handler = ngx_tcp_session_handler;
        c->write->handler = ngx_tcp_session_handler;

 //       ngx_tcp_finalize_session(r, ngx_tcp_special_response_handler(r, rc));
        return;
    }


    if (r != c->data) {
        return;
    }

    r->write_event_handler = ngx_tcp_session_empty_handler;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        ngx_del_timer(c->write);
    }

    if (c->read->eof) {
        ngx_tcp_close_session(r, 0);
        return;
    }

    ngx_tcp_finalize_connection(r);
}


static void
ngx_tcp_terminate_session(ngx_tcp_session_t *r, ngx_int_t rc)
{
    ngx_tcp_cleanup_t    *cln;
    ngx_tcp_session_t    *mr;

    mr = r->main;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp terminate session count:%d", mr->count);


    cln = mr->cleanup;
    mr->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp terminate cleanup count:%d",
                   mr->count, 0);

    if (mr->write_event_handler) {

        mr->write_event_handler = ngx_tcp_terminate_handler;
        return;
    }

    ngx_tcp_close_session(mr, rc);
}


static void
ngx_tcp_terminate_handler(ngx_tcp_session_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp terminate handler count:%d", r->count);

    r->count = 1;

    ngx_tcp_close_session(r, 0);
}


static void
ngx_tcp_finalize_connection(ngx_tcp_session_t *r)
{
    ngx_tcp_core_loc_conf_t  *clcf;

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);

    if (r->main->count != 1) {
        ngx_tcp_close_session(r, 0);
        return;
    }

    if (!ngx_terminate
         && !ngx_exiting
         && r->keepalive
         && clcf->keepalive_timeout > 0)
    {
        ngx_tcp_set_keepalive(r);
        return;
    }

    ngx_tcp_close_session(r, 0);
}

/*
static ngx_int_t
ngx_tcp_set_write_handler(ngx_tcp_session_t *r)
{
    ngx_event_t               *wev;
    ngx_tcp_core_loc_conf_t  *clcf;

    r->tcp_state = NGX_TCP_WRITING_SESSION_STATE;

    r->read_event_handler = ngx_tcp_test_reading;
    r->write_event_handler = ngx_tcp_writer;

    wev = r->connection->write;

    if (wev->ready && wev->delayed) {
        return NGX_OK;
    }

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);
    if (!wev->delayed) {
        ngx_add_timer(wev, clcf->send_timeout);
    }

    if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
        ngx_tcp_close_session(r, 0);
        return NGX_ERROR;
    }

    return NGX_OK;
}
*/
/*
static void
ngx_tcp_writer(ngx_tcp_session_t *r)
{
    int                        rc;
    ngx_event_t               *wev;
    ngx_connection_t          *c;
    ngx_tcp_core_loc_conf_t  *clcf;

    c = r->connection;
    wev = c->write;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "tcp writer handler: \"%V?%V\"", &r->uri, &r->args);

    clcf = ngx_tcp_get_module_loc_conf(r->main, ngx_tcp_core_module);

    if (wev->timedout) {
        if (!wev->delayed) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

            ngx_tcp_finalize_session(r, NGX_TCP_SESSION_TIME_OUT);
            return;
        }

        wev->timedout = 0;
        wev->delayed = 0;

        if (!wev->ready) {
            ngx_add_timer(wev, clcf->send_timeout);

            if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
                ngx_tcp_close_session(r, 0);
            }

            return;
        }

    }

    if (wev->delayed || r->aio) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, wev->log, 0,
                       "tcp writer delayed");

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_tcp_close_session(r, 0);
        }

        return;
    }

    rc = ngx_tcp_output_filter(r, NULL);

    ngx_log_debug3(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp writer output filter: %d, \"%V?%V\"",
                   rc, &r->uri, &r->args);

    if (rc == NGX_ERROR) {
        ngx_tcp_finalize_session(r, rc);
        return;
    }

    if (r == r->main && c->buffered) {

        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_tcp_close_session(r, 0);
        }

        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "tcp writer done: \"%V?%V\"", &r->uri, &r->args);

    r->write_event_handler = ngx_tcp_session_empty_handler;

    ngx_tcp_finalize_session(r, rc);
}
*/
/*
static void
ngx_tcp_session_finalizer(ngx_tcp_session_t *r)
{
    ngx_log_debug2(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp finalizer done: \"%V?%V\"", &r->uri, &r->args);

    ngx_tcp_finalize_session(r, 0);
}
*/

void
ngx_tcp_block_reading(ngx_tcp_session_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp reading blocked");

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (ngx_del_event(r->connection->read, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_tcp_close_session(r, 0);
        }
    }
}


void
ngx_tcp_test_reading(ngx_tcp_session_t *r)
{
    int                n;
    char               buf[1];
    ngx_err_t          err;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = r->connection;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp test reading");

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == 0) {
        rev->eof = 1;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = ngx_socket_errno;

        if (err != NGX_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {

        if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_tcp_close_session(r, 0);
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, err,
                  "client prematurely closed connection");

    ngx_tcp_finalize_session(r, 0);
}


static void
ngx_tcp_set_keepalive(ngx_tcp_session_t *r)
{
    int                        tcp_nodelay;
    ngx_int_t                  i;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_tcp_connection_t     *hc;
    //ngx_tcp_core_srv_conf_t  *cscf;
    ngx_tcp_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "set tcp keepalive handler");

    c->log->action = "closing session";

    hc = r->tcp_connection;

    r->keepalive = 0;

    ngx_tcp_free_session(r, 0);

    c->data = hc;

    ngx_add_timer(rev, clcf->keepalive_timeout);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = ngx_tcp_empty_handler;


    /*
     * To keep a memory footprint as small as possible for an idle
     * keepalive connection we try to free the ngx_tcp_session_t and
     * c->buffer's memory if they were allocated outside the c->pool.
     * The large header buffers are always allocated outside the c->pool and
     * are freed too.
     */

    if (ngx_pfree(c->pool, r) == NGX_OK) {
        hc->session = NULL;
    }


    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0, "hc free: %p %d",
                   hc->free, hc->nfree);

    if (hc->free) {
        for (i = 0; i < hc->nfree; i++) {
            ngx_pfree(c->pool, hc->free[i]->start);
            hc->free[i] = NULL;
        }

        hc->nfree = 0;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0, "hc busy: %p %d",
                   hc->busy, hc->nbusy);

    if (hc->busy) {
        for (i = 0; i < hc->nbusy; i++) {
            ngx_pfree(c->pool, hc->busy[i]->start);
            hc->busy[i] = NULL;
        }

        hc->nbusy = 0;
    }

    rev->handler = ngx_tcp_keepalive_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_tcp_close_connection(c);
            return;
        }
    }

    c->log->action = "keepalive";

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
            ngx_tcp_close_connection(c);
            return;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        tcp_nodelay = ngx_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay
        && clcf->tcp_nodelay
        && c->tcp_nodelay == NGX_TCP_NODELAY_UNSET)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp_nodelay");

        if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &tcp_nodelay, sizeof(int))
            == -1)
        {
#if (NGX_SOLARIS)
            /* Solaris returns EINVAL if a socket has been shut down */
            c->log_error = NGX_ERROR_IGNORE_EINVAL;
#endif

            ngx_connection_error(c, ngx_socket_errno,
                                 "setsockopt(TCP_NODELAY) failed");

            c->log_error = NGX_ERROR_INFO;
            ngx_tcp_close_connection(c);
            return;
        }

        c->tcp_nodelay = NGX_TCP_NODELAY_SET;
    }

#if 0
    /* if ngx_tcp_session_t was freed then we need some other place */
    r->tcp_state = NGX_TCP_KEEPALIVE_STATE;
#endif

    c->idle = 1;
    ngx_reusable_connection(c, 1);

    if (rev->ready) {
        ngx_post_event(rev, &ngx_posted_events);
    }
}


static void
ngx_tcp_keepalive_handler(ngx_event_t *rev)
{
    size_t             size;
    ssize_t            n;
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp keepalive handler");

    if (rev->timedout || c->close) {
        ngx_tcp_close_connection(c);
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
            ngx_tcp_close_connection(c);
            return;
        }
    }

#endif

    b = c->buffer;
    size = b->end - b->start;

    if (b->pos == NULL) {

        /*
         * The c->buffer's memory was freed by ngx_tcp_set_keepalive().
         * However, the c->buffer->start and c->buffer->end were not changed
         * to keep the buffer size.
         */

        b->pos = ngx_palloc(c->pool, size);
        if (b->pos == NULL) {
            ngx_tcp_close_connection(c);
            return;
        }

        b->start = b->pos;
        b->last = b->pos;
        b->end = b->pos + size;
    }

    /*
     * MSIE closes a keepalive connection with RST flag
     * so we ignore ECONNRESET here.
     */

    c->log_error = NGX_ERROR_IGNORE_ECONNRESET;
    ngx_set_socket_errno(0);

    n = c->recv(c, b->last, size);
    c->log_error = NGX_ERROR_INFO;

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_tcp_close_connection(c);
        }

        /*
         * Like ngx_tcp_set_keepalive() we are trying to not hold
         * c->buffer's memory for a keepalive connection.
         */

        if (ngx_pfree(c->pool, b->start) == NGX_OK) {

            /*
             * the special note that c->buffer's memory was freed
             */

            b->pos = NULL;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_tcp_close_connection(c);
        return;
    }

    c->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                      "client %V closed keepalive connection", &c->addr_text);
        ngx_tcp_close_connection(c);
        return;
    }

    b->last += n;

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
#endif

    c->log->handler = ngx_tcp_log_error;
    c->log->action = "reading client session line";

    c->idle = 0;
    ngx_reusable_connection(c, 0);

    ngx_tcp_init_session(rev);
}


void
ngx_tcp_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, wev->log, 0, "tcp empty handler");

    return;
}


void
ngx_tcp_session_empty_handler(ngx_tcp_session_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp session empty handler");

    return;
}

/*
ngx_int_t
ngx_tcp_send_special(ngx_tcp_session_t *r, ngx_uint_t flags)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (flags & NGX_TCP_LAST) {

        if (r == r->main) {
            b->last_buf = 1;

        } else {
            b->sync = 1;
            b->last_in_chain = 1;
        }
    }

    if (flags & NGX_TCP_FLUSH) {
        b->flush = 1;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_tcp_output_filter(r, &out);
}
*/

static void
ngx_tcp_close_session(ngx_tcp_session_t *r, ngx_int_t rc)
{
    ngx_connection_t  *c;

    r = r->main;
    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp session count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "tcp session count is zero");
    }

    r->count--;

    if (r->count) {
        return;
    }

    ngx_tcp_free_session(r, rc);
    ngx_tcp_close_connection(c);
}


static void
ngx_tcp_free_session(ngx_tcp_session_t *r, ngx_int_t rc)
{
    ngx_log_t                 *log;
    struct linger              linger;
    ngx_tcp_cleanup_t        *cln;
    ngx_tcp_log_ctx_t        *ctx;
    ngx_tcp_core_loc_conf_t  *clcf;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, log, 0, "tcp close session");

    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "tcp session already closed");
        return;
    }

    for (cln = r->cleanup; cln; cln = cln->next) {
        if (cln->handler) {
            cln->handler(cln->data);
        }
    }

#if (NGX_STAT_STUB)

    if (r->stat_reading) {
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    }

    if (r->stat_writing) {
        (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
    }

#endif

    log->action = "logging session";

    ngx_tcp_log_session(r);

    log->action = "closing session";

    if (r->connection->timedout) {
        clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);

        if (clcf->reset_timedout_connection) {
            linger.l_onoff = 1;
            linger.l_linger = 0;

            if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
                           (const void *) &linger, sizeof(struct linger)) == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                              "setsockopt(SO_LINGER) failed");
            }
        }
    }

    /* the various session strings were allocated from r->pool */
    ctx = log->data;
    ctx->session = NULL;

    r->connection->destroyed = 1;

    ngx_destroy_pool(r->pool);
}


static void
ngx_tcp_log_session(ngx_tcp_session_t *r)
{
    ngx_uint_t                  i, n;
    ngx_tcp_handler_pt        *log_handler;
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_tcp_get_module_main_conf(r, ngx_tcp_core_module);

    log_handler = cmcf->phases[NGX_TCP_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_TCP_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](r);
    }
}


static void
ngx_tcp_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "close tcp connection: %d", c->fd);

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


static u_char *
ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_tcp_session_t  *r;
    ngx_tcp_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
    len -= p - buf;

    r = ctx->session;

    if (r) {
        return r->log_handler(r, ctx->current_session, p, len);

    } else {
        p = ngx_snprintf(p, len, ", server: %V",
                         &ctx->connection->listening->addr_text);
    }

    return p;
}


static u_char *
ngx_tcp_log_error_handler(ngx_tcp_session_t *r, ngx_tcp_session_t *sr,
    u_char *buf, size_t len)
{
    u_char                    *p;
    ngx_tcp_upstream_t       *u;
    ngx_tcp_core_srv_conf_t  *cscf;

    cscf = ngx_tcp_get_module_srv_conf(r, ngx_tcp_core_module);

    p = ngx_snprintf(buf, len, ", server: %V", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r != sr) {
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {
        len -= p - buf;
        buf = p;
    }

    return buf;
}

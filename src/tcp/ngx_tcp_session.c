
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


static void ngx_tcp_init_session(ngx_event_t *ev);
static void ngx_tcp_process_session_line(ngx_event_t *rev);

static ngx_int_t ngx_tcp_process_host(ngx_tcp_session_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_tcp_process_connection(ngx_tcp_session_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

static void ngx_tcp_process_session(ngx_tcp_session_t *r);
static ssize_t ngx_tcp_validate_host(ngx_tcp_session_t *r, u_char **host,
    size_t len, ngx_uint_t alloc);
static ngx_int_t ngx_tcp_find_virtual_server(ngx_tcp_session_t *r,
    u_char *host, size_t len);

static void ngx_tcp_session_handler(ngx_event_t *ev);
static void ngx_tcp_terminate_session(ngx_tcp_session_t *r, ngx_int_t rc);
static void ngx_tcp_terminate_handler(ngx_tcp_session_t *r);
static void ngx_tcp_finalize_connection(ngx_tcp_session_t *r);
static ngx_int_t ngx_tcp_set_write_handler(ngx_tcp_session_t *r);
static void ngx_tcp_writer(ngx_tcp_session_t *r);
static void ngx_tcp_session_finalizer(ngx_tcp_session_t *r);

static void ngx_tcp_set_keepalive(ngx_tcp_session_t *r);
static void ngx_tcp_keepalive_handler(ngx_event_t *ev);
static void ngx_tcp_set_lingering_close(ngx_tcp_session_t *r);
static void ngx_tcp_close_session(ngx_tcp_session_t *r, ngx_int_t error);
static void ngx_tcp_free_session(ngx_tcp_session_t *r, ngx_int_t error);
static void ngx_tcp_log_session(ngx_tcp_session_t *r);
static void ngx_tcp_close_connection(ngx_connection_t *c);

static u_char *ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len);
static u_char *ngx_tcp_log_error_handler(ngx_tcp_session_t *r,
    ngx_tcp_session_t *sr, u_char *buf, size_t len);


static char *ngx_tcp_client_errors[] = {

    /* NGX_TCP_PARSE_INVALID_METHOD */
    "client sent invalid method",

    /* NGX_TCP_PARSE_INVALID_SESSION */
    "client sent invalid session",

    /* NGX_TCP_PARSE_INVALID_09_METHOD */
    "client sent invalid method in session"
};


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

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
#endif

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
#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
#endif
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
    ngx_tcp_session_t         *r;
    struct sockaddr_in         *sin;
    ngx_tcp_port_t            *port;
    ngx_tcp_in_addr_t         *addr;
    ngx_tcp_log_ctx_t         *ctx;
    ngx_tcp_addr_conf_t       *addr_conf;
    ngx_tcp_connection_t      *hc;
    ngx_tcp_core_srv_conf_t   *cscf;
    ngx_tcp_core_loc_conf_t   *clcf;
    ngx_tcp_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
    ngx_tcp_in6_addr_t        *addr6;
#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
#endif

    c = rev->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "rev client timed out");

        ngx_tcp_close_connection(c);
        return;
    }

    c->sessions++;

    hc = c->data;

    if (hc == NULL) {
        hc = ngx_pcalloc(c->pool, sizeof(ngx_tcp_connection_t));
        if (hc == NULL) {
            ngx_tcp_close_connection(c);
            return;
        }
    }

    r = hc->session;

    if (r) {
        ngx_memzero(r, sizeof(ngx_tcp_session_t));

        r->pipeline = hc->pipeline;

    } else {
        r = ngx_pcalloc(c->pool, sizeof(ngx_tcp_session_t));
        if (r == NULL) {
            ngx_tcp_close_connection(c);
            return;
        }

        hc->session = r;
    }

    c->data = r;
    r->tcp_connection = hc;

    c->sent = 0;
    r->signature = NGX_TCP_MODULE;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    r->connection = c;

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

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

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

    r->virtual_names = addr_conf->virtual_names;

    /* the default server configuration for the address:port */
    cscf = addr_conf->default_server;

    r->main_conf = cscf->ctx->main_conf;
    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    rev->handler = ngx_tcp_process_session_line;
    r->read_event_handler = ngx_tcp_block_reading;

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);
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

    r->pool = ngx_create_pool(cscf->session_pool_size, c->log);
    if (r->pool == NULL) {
        ngx_tcp_close_connection(c);
        return;
    }


    if (ngx_list_init(&r->headers_out.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_destroy_pool(r->pool);
        ngx_tcp_close_connection(c);
        return;
    }

    r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_tcp_max_module);
    if (r->ctx == NULL) {
        ngx_destroy_pool(r->pool);
        ngx_tcp_close_connection(c);
        return;
    }

    cmcf = ngx_tcp_get_module_main_conf(r, ngx_tcp_core_module);

    r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(ngx_tcp_variable_value_t));
    if (r->variables == NULL) {
        ngx_destroy_pool(r->pool);
        ngx_tcp_close_connection(c);
        return;
    }

    c->single_connection = 1;
    c->destroyed = 0;

    r->main = r;
    r->count = 1;

    tp = ngx_timeofday();
    r->start_sec = tp->sec;
    r->start_msec = tp->msec;

    r->tcp_state = NGX_TCP_READING_SESSION_STATE;

    ctx = c->log->data;
    ctx->session = r;
    ctx->current_session = r;
    r->log_handler = ngx_tcp_log_error_handler;

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
    r->stat_reading = 1;
    (void) ngx_atomic_fetch_add(ngx_stat_sessions, 1);
#endif

    rev->handler(rev);
}

static void
ngx_tcp_process_session_line(ngx_event_t *rev)
{
    u_char                    *host;
    ssize_t                    n;
    ngx_int_t                  rc, rv;
    ngx_connection_t          *c;
    ngx_tcp_session_t        *r;
    ngx_tcp_core_srv_conf_t  *cscf;

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, rev->log, 0,
                   "tcp process session line");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_tcp_close_session(r, NGX_TCP_SESSION_TIME_OUT);
        return;
    }

    rc = NGX_AGAIN;

    for ( ;; ) {

        if (rc == NGX_AGAIN) {
            n = ngx_tcp_read_session_header(r);

            if (n == NGX_AGAIN || n == NGX_ERROR) {
                return;
            }
        }

        rc = ngx_tcp_parse_session_line(r, r->header_in);

        if (rc == NGX_OK) {

            /* the session line has been parsed successfully */

            r->session_line.len = r->session_end - r->session_start;
            r->session_line.data = r->session_start;
            r->session_length = r->header_in->pos - r->session_start;


            if (r->args_start) {
                r->uri.len = r->args_start - 1 - r->uri_start;
            } else {
                r->uri.len = r->uri_end - r->uri_start;
            }


            if (r->complex_uri || r->quoted_uri) {

                r->uri.data = ngx_pnalloc(r->pool, r->uri.len + 1);
                if (r->uri.data == NULL) {
                    ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                    return;
                }

                cscf = ngx_tcp_get_module_srv_conf(r, ngx_tcp_core_module);

                rc = ngx_tcp_parse_complex_uri(r, cscf->merge_slashes);

                if (rc == NGX_TCP_PARSE_INVALID_SESSION) {
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent invalid session");
                    ngx_tcp_finalize_session(r, NGX_TCP_BAD_SESSION);
                    return;
                }

            } else {
                r->uri.data = r->uri_start;
            }


            r->unparsed_uri.len = r->uri_end - r->uri_start;
            r->unparsed_uri.data = r->uri_start;

            r->valid_unparsed_uri = r->space_in_uri ? 0 : 1;

            r->method_name.len = r->method_end - r->session_start + 1;
            r->method_name.data = r->session_line.data;


            if (r->tcp_protocol.data) {
                r->tcp_protocol.len = r->session_end - r->tcp_protocol.data;
            }


            if (r->uri_ext) {
                if (r->args_start) {
                    r->exten.len = r->args_start - 1 - r->uri_ext;
                } else {
                    r->exten.len = r->uri_end - r->uri_ext;
                }

                r->exten.data = r->uri_ext;
            }


            if (r->args_start && r->uri_end > r->args_start) {
                r->args.len = r->uri_end - r->args_start;
                r->args.data = r->args_start;
            }

#if (NGX_WIN32)
            {
            u_char  *p, *last;

            p = r->uri.data;
            last = r->uri.data + r->uri.len;

            while (p < last) {

                if (*p++ == ':') {

                    /*
                     * this check covers "::$data", "::$index_allocation" and
                     * ":$i30:$index_allocation"
                     */

                    if (p < last && *p == '$') {
                        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                      "client sent unsafe win32 URI");
                        ngx_tcp_finalize_session(r, NGX_TCP_BAD_SESSION);
                        return;
                    }
                }
            }

            p = r->uri.data + r->uri.len - 1;

            while (p > r->uri.data) {

                if (*p == ' ') {
                    p--;
                    continue;
                }

                if (*p == '.') {
                    p--;
                    continue;
                }

                break;
            }

            if (p != r->uri.data + r->uri.len - 1) {
                r->uri.len = p + 1 - r->uri.data;
                ngx_tcp_set_exten(r);
            }

            }
#endif

            ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                           "tcp session line: \"%V\"", &r->session_line);

            ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                           "tcp uri: \"%V\"", &r->uri);

            ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                           "tcp args: \"%V\"", &r->args);

            ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                           "tcp exten: \"%V\"", &r->exten);

            if (r->host_start && r->host_end) {

                host = r->host_start;
                n = ngx_tcp_validate_host(r, &host,
                                           r->host_end - r->host_start, 0);

                if (n == 0) {
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent invalid host in session line");
                    ngx_tcp_finalize_session(r, NGX_TCP_BAD_SESSION);
                    return;
                }

                if (n < 0) {
                    ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                    return;
                }

                r->headers_in.server.len = n;
                r->headers_in.server.data = host;
            }

            if (r->tcp_version < NGX_TCP_VERSION_10) {

                if (ngx_tcp_find_virtual_server(r, r->headers_in.server.data,
                                                 r->headers_in.server.len)
                    == NGX_ERROR)
                {
                    ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                    return;
                }

                ngx_tcp_process_session(r);
                return;
            }


            if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                              sizeof(ngx_table_elt_t))
                != NGX_OK)
            {
                ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                return;
            }


            if (ngx_array_init(&r->headers_in.cookies, r->pool, 2,
                               sizeof(ngx_table_elt_t *))
                != NGX_OK)
            {
                ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                return;
            }

            c->log->action = "reading client session headers";

            rev->handler = ngx_tcp_process_session_headers;
            ngx_tcp_process_session_headers(rev);

            return;
        }

        if (rc != NGX_AGAIN) {

            /* there was error while a session line parsing */

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          ngx_tcp_client_errors[rc - NGX_TCP_CLIENT_ERROR]);
            ngx_tcp_finalize_session(r, NGX_TCP_BAD_SESSION);
            return;
        }

        /* NGX_AGAIN: a session line parsing is still incomplete */

        if (r->header_in->pos == r->header_in->end) {

            rv = ngx_tcp_alloc_large_header_buffer(r, 1);

            if (rv == NGX_ERROR) {
                ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (rv == NGX_DECLINED) {
                r->session_line.len = r->header_in->end - r->session_start;
                r->session_line.data = r->session_start;

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent too long URI");
                ngx_tcp_finalize_session(r, NGX_TCP_SESSION_URI_TOO_LARGE);
                return;
            }
        }
    }
}


static void
ngx_tcp_process_session_headers(ngx_event_t *rev)
{
    u_char                     *p;
    size_t                      len;
    ssize_t                     n;
    ngx_int_t                   rc, rv;
    ngx_table_elt_t            *h;
    ngx_connection_t           *c;
    ngx_tcp_header_t          *hh;
    ngx_tcp_session_t         *r;
    ngx_tcp_core_srv_conf_t   *cscf;
    ngx_tcp_core_main_conf_t  *cmcf;

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, rev->log, 0,
                   "tcp process session header line");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_tcp_close_session(r, NGX_TCP_SESSION_TIME_OUT);
        return;
    }

    cmcf = ngx_tcp_get_module_main_conf(r, ngx_tcp_core_module);
    cscf = ngx_tcp_get_module_srv_conf(r, ngx_tcp_core_module);

    rc = NGX_AGAIN;

    for ( ;; ) {

        if (rc == NGX_AGAIN) {

            if (r->header_in->pos == r->header_in->end) {

                rv = ngx_tcp_alloc_large_header_buffer(r, 0);

                if (rv == NGX_ERROR) {
                    ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (rv == NGX_DECLINED) {
                    p = r->header_name_start;

                    r->lingering_close = 1;

                    if (p == NULL) {
                        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                      "client sent too large session");
                        ngx_tcp_finalize_session(r,
                                            NGX_TCP_SESSION_HEADER_TOO_LARGE);
                        return;
                    }

                    len = r->header_in->end - p;

                    if (len > NGX_MAX_ERROR_STR - 300) {
                        len = NGX_MAX_ERROR_STR - 300;
                        p[len++] = '.'; p[len++] = '.'; p[len++] = '.';
                    }

                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent too long header line: \"%*s\"",
                                  len, r->header_name_start);

                    ngx_tcp_finalize_session(r,
                                            NGX_TCP_SESSION_HEADER_TOO_LARGE);
                    return;
                }
            }

            n = ngx_tcp_read_session_header(r);

            if (n == NGX_AGAIN || n == NGX_ERROR) {
                return;
            }
        }

        rc = ngx_tcp_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);

        if (rc == NGX_OK) {

            r->session_length += r->header_in->pos - r->header_name_start;

            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);
                continue;
            }

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->headers_in.headers);
            if (h == NULL) {
                ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                return;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                           "tcp header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NGX_TCP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                           "tcp header done");

            r->session_length += r->header_in->pos - r->header_name_start;

            r->tcp_state = NGX_TCP_PROCESS_SESSION_STATE;

            rc = ngx_tcp_process_session_header(r);

            if (rc != NGX_OK) {
                return;
            }

            ngx_tcp_process_session(r);

            return;
        }

        if (rc == NGX_AGAIN) {

            /* a header line parsing is still not complete */

            continue;
        }

        /* rc == NGX_TCP_PARSE_INVALID_HEADER: "\r" is not followed by "\n" */

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid header line: \"%*s\\r...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start);
        ngx_tcp_finalize_session(r, NGX_TCP_BAD_SESSION);
        return;
    }
}


static ssize_t
ngx_tcp_read_session_header(ngx_tcp_session_t *r)
{
    ssize_t                    n;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_tcp_core_srv_conf_t  *cscf;

    c = r->connection;
    rev = c->read;

    n = r->header_in->last - r->header_in->pos;

    if (n > 0) {
        return n;
    }

    if (rev->ready) {
        n = c->recv(c, r->header_in->last,
                    r->header_in->end - r->header_in->last);
    } else {
        n = NGX_AGAIN;
    }

    if (n == NGX_AGAIN) {
        if (!rev->timer_set) {
            cscf = ngx_tcp_get_module_srv_conf(r, ngx_tcp_core_module);
            ngx_add_timer(rev, cscf->client_header_timeout);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client prematurely closed connection");
    }

    if (n == 0 || n == NGX_ERROR) {
        c->error = 1;
        c->log->action = "reading client session headers";

        ngx_tcp_finalize_session(r, NGX_TCP_BAD_SESSION);
        return NGX_ERROR;
    }

    r->header_in->last += n;

    return n;
}


static ngx_int_t
ngx_tcp_alloc_large_header_buffer(ngx_tcp_session_t *r,
    ngx_uint_t session_line)
{
    u_char                    *old, *new;
    ngx_buf_t                 *b;
    ngx_tcp_connection_t     *hc;
    ngx_tcp_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp alloc large header buffer");

    if (session_line && r->state == 0) {

        /* the client fills up the buffer with "\r\n" */

        r->header_in->pos = r->header_in->start;
        r->header_in->last = r->header_in->start;

        return NGX_OK;
    }

    old = session_line ? r->session_start : r->header_name_start;

    cscf = ngx_tcp_get_module_srv_conf(r, ngx_tcp_core_module);

    if (r->state != 0
        && (size_t) (r->header_in->pos - old)
                                     >= cscf->large_client_header_buffers.size)
    {
        return NGX_DECLINED;
    }

    hc = r->tcp_connection;

    if (hc->nfree) {
        b = hc->free[--hc->nfree];

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                       "tcp large header free: %p %uz",
                       b->pos, b->end - b->last);

    } else if (hc->nbusy < cscf->large_client_header_buffers.num) {

        if (hc->busy == NULL) {
            hc->busy = ngx_palloc(r->connection->pool,
                  cscf->large_client_header_buffers.num * sizeof(ngx_buf_t *));
            if (hc->busy == NULL) {
                return NGX_ERROR;
            }
        }

        b = ngx_create_temp_buf(r->connection->pool,
                                cscf->large_client_header_buffers.size);
        if (b == NULL) {
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                       "tcp large header alloc: %p %uz",
                       b->pos, b->end - b->last);

    } else {
        return NGX_DECLINED;
    }

    hc->busy[hc->nbusy++] = b;

    if (r->state == 0) {
        /*
         * r->state == 0 means that a header line was parsed successfully
         * and we do not need to copy incomplete header line and
         * to relocate the parser header pointers
         */

        r->header_in = b;

        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp large header copy: %d", r->header_in->pos - old);

    new = b->start;

    ngx_memcpy(new, old, r->header_in->pos - old);

    b->pos = new + (r->header_in->pos - old);
    b->last = new + (r->header_in->pos - old);

    if (session_line) {
        r->session_start = new;

        if (r->session_end) {
            r->session_end = new + (r->session_end - old);
        }

        r->method_end = new + (r->method_end - old);

        r->uri_start = new + (r->uri_start - old);
        r->uri_end = new + (r->uri_end - old);

        if (r->schema_start) {
            r->schema_start = new + (r->schema_start - old);
            r->schema_end = new + (r->schema_end - old);
        }

        if (r->host_start) {
            r->host_start = new + (r->host_start - old);
            if (r->host_end) {
                r->host_end = new + (r->host_end - old);
            }
        }

        if (r->port_start) {
            r->port_start = new + (r->port_start - old);
            r->port_end = new + (r->port_end - old);
        }

        if (r->uri_ext) {
            r->uri_ext = new + (r->uri_ext - old);
        }

        if (r->args_start) {
            r->args_start = new + (r->args_start - old);
        }

        if (r->tcp_protocol.data) {
            r->tcp_protocol.data = new + (r->tcp_protocol.data - old);
        }

    } else {
        r->header_name_start = new;
        r->header_name_end = new + (r->header_name_end - old);
        r->header_start = new + (r->header_start - old);
        r->header_end = new + (r->header_end - old);
    }

    r->header_in = b;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_process_header_line(ngx_tcp_session_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_process_unique_header_line(ngx_tcp_session_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent duplicate header line: \"%V: %V\", "
                  "previous value: \"%V: %V\"",
                  &h->key, &h->value, &(*ph)->key, &(*ph)->value);

    ngx_tcp_finalize_session(r, NGX_TCP_BAD_SESSION);

    return NGX_ERROR;
}


static ngx_int_t
ngx_tcp_process_host(ngx_tcp_session_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char   *host;
    ssize_t   len;

    if (r->headers_in.host == NULL) {
        r->headers_in.host = h;
    }

    host = h->value.data;
    len = ngx_tcp_validate_host(r, &host, h->value.len, 0);

    if (len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid host header");
        ngx_tcp_finalize_session(r, NGX_TCP_BAD_SESSION);
        return NGX_ERROR;
    }

    if (len < 0) {
        ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (r->headers_in.server.len) {
        return NGX_OK;
    }

    r->headers_in.server.len = len;
    r->headers_in.server.data = host;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_process_connection(ngx_tcp_session_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    if (ngx_strcasestrn(h->value.data, "close", 5 - 1)) {
        r->headers_in.connection_type = NGX_TCP_CONNECTION_CLOSE;

    } else if (ngx_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = NGX_TCP_CONNECTION_KEEP_ALIVE;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_process_user_agent(ngx_tcp_session_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char  *user_agent, *msie;

    if (r->headers_in.user_agent) {
        return NGX_OK;
    }

    r->headers_in.user_agent = h;

    /* check some widespread browsers while the header is in CPU cache */

    user_agent = h->value.data;

    msie = ngx_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + h->value.len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (ngx_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
                    r->headers_in.msie6 = 1;
                }
                break;
            }
        }

#if 0
        /* MSIE ignores the SSL "close notify" alert */
        if (c->ssl) {
            c->ssl->no_send_shutdown = 1;
        }
#endif
    }

    if (ngx_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (ngx_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (ngx_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (ngx_strstrn(user_agent, "Safari/", 7 - 1)
                   && ngx_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (ngx_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_process_cookie(ngx_tcp_session_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **cookie;

    cookie = ngx_array_push(&r->headers_in.cookies);
    if (cookie) {
        *cookie = h;
        return NGX_OK;
    }

    ngx_tcp_close_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);

    return NGX_ERROR;
}


static ngx_int_t
ngx_tcp_process_session_header(ngx_tcp_session_t *r)
{
    if (ngx_tcp_find_virtual_server(r, r->headers_in.server.data,
                                     r->headers_in.server.len)
        == NGX_ERROR)
    {
        ngx_tcp_finalize_session(r, NGX_TCP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (r->headers_in.host == NULL && r->tcp_version > NGX_TCP_VERSION_10) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                   "client sent TCP/1.1 session without \"Host\" header");
        ngx_tcp_finalize_session(r, NGX_TCP_BAD_SESSION);
        return NGX_ERROR;
    }

    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            ngx_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \"Content-Length\" header");
            ngx_tcp_finalize_session(r, NGX_TCP_LENGTH_REQUIRED);
            return NGX_ERROR;
        }
    }

    if (r->method & NGX_TCP_PUT && r->headers_in.content_length_n == -1) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent %V method without \"Content-Length\" header",
                  &r->method_name);
        ngx_tcp_finalize_session(r, NGX_TCP_LENGTH_REQUIRED);
        return NGX_ERROR;
    }

    if (r->method & NGX_TCP_TRACE) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent TRACE method");
        ngx_tcp_finalize_session(r, NGX_TCP_NOT_ALLOWED);
        return NGX_ERROR;
    }

    if (r->headers_in.transfer_encoding
        && ngx_strcasestrn(r->headers_in.transfer_encoding->value.data,
                           "chunked", 7 - 1))
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent \"Transfer-Encoding: chunked\" header");
        ngx_tcp_finalize_session(r, NGX_TCP_LENGTH_REQUIRED);
        return NGX_ERROR;
    }

    if (r->headers_in.connection_type == NGX_TCP_CONNECTION_KEEP_ALIVE) {
        if (r->headers_in.keep_alive) {
            r->headers_in.keep_alive_n =
                            ngx_atotm(r->headers_in.keep_alive->value.data,
                                      r->headers_in.keep_alive->value.len);
        }
    }

    return NGX_OK;
}


static void
ngx_tcp_process_session(ngx_tcp_session_t *r)
{
    ngx_connection_t  *c;

    c = r->connection;

    if (r->plain_tcp) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent plain TCP session to TCPS port");
        ngx_tcp_finalize_session(r, NGX_TCP_TO_TCPS);
        return;
    }


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


static ssize_t
ngx_tcp_validate_host(ngx_tcp_session_t *r, u_char **host, size_t len,
    ngx_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = len;
    host_len = len;

    h = *host;

    state = sw_usual;

    for (i = 0; i < len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return 0;
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        case '\0':
            return 0;

        default:

            if (ngx_path_separator(ch)) {
                return 0;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (alloc) {
        *host = ngx_pnalloc(r->pool, host_len);
        if (*host == NULL) {
            return -1;
        }

        ngx_strlow(*host, h, host_len);
    }

    return host_len;
}


static ngx_int_t
ngx_tcp_find_virtual_server(ngx_tcp_session_t *r, u_char *host, size_t len)
{
    ngx_tcp_core_loc_conf_t  *clcf;
    ngx_tcp_core_srv_conf_t  *cscf;

    if (r->virtual_names == NULL) {
        return NGX_DECLINED;
    }

    cscf = ngx_hash_find_combined(&r->virtual_names->names,
                                  ngx_hash_key(host, len), host, len);

    if (cscf) {
        goto found;
    }

#if (NGX_PCRE)

    if (len && r->virtual_names->nregex) {
        ngx_int_t                n;
        ngx_uint_t               i;
        ngx_str_t                name;
        ngx_tcp_server_name_t  *sn;

        name.len = len;
        name.data = host;

        sn = r->virtual_names->regex;

        for (i = 0; i < r->virtual_names->nregex; i++) {

            n = ngx_tcp_regex_exec(r, sn[i].regex, &name);

            if (n == NGX_OK) {
                cscf = sn[i].server;
                goto found;
            }

            if (n == NGX_DECLINED) {
                continue;
            }

            return NGX_ERROR;
        }
    }

#endif

    return NGX_DECLINED;

found:

    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);
    r->connection->log->file = clcf->error_log->file;

    if (!(r->connection->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
        r->connection->log->log_level = clcf->error_log->log_level;
    }

    return NGX_OK;
}


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
    ngx_tcp_session_t         *r;
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
    }
}


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

    for (p = &r->main->posted_sessions; *p; p = &(*p)->next) { /* void */ }

    *p = pr;

    return NGX_OK;
}


void
ngx_tcp_finalize_session(ngx_tcp_session_t *r, ngx_int_t rc)
{
    ngx_connection_t          *c;
    ngx_tcp_session_t        *pr;
    ngx_tcp_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug5(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp finalize session: %d, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == c->data, r->main->count);

    if (rc == NGX_DONE) {
        ngx_tcp_finalize_connection(r);
        return;
    }

    if (rc == NGX_OK && r->filter_finalize) {
        c->error = 1;
    }

    if (rc == NGX_DECLINED) {
        r->content_handler = NULL;
        r->write_event_handler = ngx_tcp_core_run_phases;
        ngx_tcp_core_run_phases(r);
        return;
    }

    if (r != r->main && r->post_subsession) {
        rc = r->post_subsession->handler(r, r->post_subsession->data, rc);
    }

    if (rc == NGX_ERROR
        || rc == NGX_TCP_SESSION_TIME_OUT
        || rc == NGX_TCP_CLIENT_CLOSED_SESSION
        || c->error)
    {
        if (ngx_tcp_post_action(r) == NGX_OK) {
            return;
        }

        if (r->main->blocked) {
            r->write_event_handler = ngx_tcp_session_finalizer;
        }

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

        ngx_tcp_finalize_session(r, ngx_tcp_special_response_handler(r, rc));
        return;
    }

    if (r != r->main) {

        if (r->buffered || r->postponed) {

            if (ngx_tcp_set_write_handler(r) != NGX_OK) {
                ngx_tcp_terminate_session(r, 0);
            }

            return;
        }

        pr = r->parent;

        if (r == c->data) {

            r->main->count--;
            r->main->subsessions++;

            if (!r->logged) {

                clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);

                if (clcf->log_subsession) {
                    ngx_tcp_log_session(r);
                }

                r->logged = 1;

            } else {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              "subsession: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            if (pr->postponed && pr->postponed->session == r) {
                pr->postponed = pr->postponed->next;
            }

            c->data = pr;

        } else {

            ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
                           "tcp finalize non-active session: \"%V?%V\"",
                           &r->uri, &r->args);

            r->write_event_handler = ngx_tcp_session_finalizer;

            if (r->waited) {
                r->done = 1;
            }
        }

        if (ngx_tcp_post_session(pr, NULL) != NGX_OK) {
            r->main->count++;
            ngx_tcp_terminate_session(r, 0);
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
                       "tcp wake parent session: \"%V?%V\"",
                       &pr->uri, &pr->args);

        return;
    }

    if (r->buffered || c->buffered || r->postponed || r->blocked) {

        if (ngx_tcp_set_write_handler(r) != NGX_OK) {
            ngx_tcp_terminate_session(r, 0);
        }

        return;
    }

    if (r != c->data) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "tcp finalize non-active session: \"%V?%V\"",
                      &r->uri, &r->args);
        return;
    }

    r->done = 1;
    r->write_event_handler = ngx_tcp_session_empty_handler;

    if (!r->post_action) {
        r->session_complete = 1;
    }

    if (ngx_tcp_post_action(r) == NGX_OK) {
        return;
    }

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
    ngx_tcp_ephemeral_t  *e;

    mr = r->main;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp terminate session count:%d", mr->count);

    if (rc > 0 && (mr->headers_out.status == 0 || mr->connection->sent == 0)) {
        mr->headers_out.status = rc;
    }

    cln = mr->cleanup;
    mr->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp terminate cleanup count:%d blk:%d",
                   mr->count, mr->blocked);

    if (mr->write_event_handler) {

        if (mr->blocked) {
            return;
        }

        e = ngx_tcp_ephemeral(mr);
        mr->posted_sessions = NULL;
        mr->write_event_handler = ngx_tcp_terminate_handler;
        (void) ngx_tcp_post_session(mr, &e->terminal_posted_session);
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

        if (r->discard_body) {
            r->read_event_handler = ngx_tcp_discarded_session_body_handler;
            ngx_add_timer(r->connection->read, clcf->lingering_timeout);

            if (r->lingering_time == 0) {
                r->lingering_time = ngx_time()
                                      + (time_t) (clcf->lingering_time / 1000);
            }
        }

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

    if (clcf->lingering_close == NGX_TCP_LINGERING_ALWAYS
        || (clcf->lingering_close == NGX_TCP_LINGERING_ON
            && (r->lingering_close
                || r->header_in->pos < r->header_in->last
                || r->connection->read->ready)))
    {
        ngx_tcp_set_lingering_close(r);
        return;
    }

    ngx_tcp_close_session(r, 0);
}


static ngx_int_t
ngx_tcp_set_write_handler(ngx_tcp_session_t *r)
{
    ngx_event_t               *wev;
    ngx_tcp_core_loc_conf_t  *clcf;

    r->tcp_state = NGX_TCP_WRITING_SESSION_STATE;

    r->read_event_handler = r->discard_body ?
                                ngx_tcp_discarded_session_body_handler:
                                ngx_tcp_test_reading;
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

    if (r->buffered || r->postponed || (r == r->main && c->buffered)) {

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


static void
ngx_tcp_session_finalizer(ngx_tcp_session_t *r)
{
    ngx_log_debug2(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "tcp finalizer done: \"%V?%V\"", &r->uri, &r->args);

    ngx_tcp_finalize_session(r, 0);
}


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
    ngx_buf_t                 *b, *f;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_tcp_connection_t     *hc;
    ngx_tcp_core_srv_conf_t  *cscf;
    ngx_tcp_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "set tcp keepalive handler");

    if (r->discard_body) {
        r->write_event_handler = ngx_tcp_session_empty_handler;
        r->lingering_time = ngx_time() + (time_t) (clcf->lingering_time / 1000);
        ngx_add_timer(rev, clcf->lingering_timeout);
        return;
    }

    c->log->action = "closing session";

    hc = r->tcp_connection;
    b = r->header_in;

    if (b->pos < b->last) {

        /* the pipelined session */

        if (b != c->buffer) {

            /*
             * If the large header buffers were allocated while the previous
             * session processing then we do not use c->buffer for
             * the pipelined session (see ngx_tcp_init_session()).
             *
             * Now we would move the large header buffers to the free list.
             */

            cscf = ngx_tcp_get_module_srv_conf(r, ngx_tcp_core_module);

            if (hc->free == NULL) {
                hc->free = ngx_palloc(c->pool,
                  cscf->large_client_header_buffers.num * sizeof(ngx_buf_t *));

                if (hc->free == NULL) {
                    ngx_tcp_close_session(r, 0);
                    return;
                }
            }

            for (i = 0; i < hc->nbusy - 1; i++) {
                f = hc->busy[i];
                hc->free[hc->nfree++] = f;
                f->pos = f->start;
                f->last = f->start;
            }

            hc->busy[0] = b;
            hc->nbusy = 1;
        }
    }

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

    if (b->pos < b->last) {

        ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "pipelined session");

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
#endif

        hc->pipeline = 1;
        c->log->action = "reading client pipelined session line";

        rev->handler = ngx_tcp_init_session;
        ngx_post_event(rev, &ngx_posted_events);
        return;
    }

    hc->pipeline = 0;

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

    b = c->buffer;

    if (ngx_pfree(c->pool, b->start) == NGX_OK) {

        /*
         * the special note for ngx_tcp_keepalive_handler() that
         * c->buffer's memory was freed
         */

        b->pos = NULL;

    } else {
        b->pos = b->start;
        b->last = b->start;
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


static void
ngx_tcp_set_lingering_close(ngx_tcp_session_t *r)
{
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_tcp_core_loc_conf_t  *clcf;

    c = r->connection;

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);

    rev = c->read;
    rev->handler = ngx_tcp_lingering_close_handler;

    r->lingering_time = ngx_time() + (time_t) (clcf->lingering_time / 1000);
    ngx_add_timer(rev, clcf->lingering_timeout);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_close_session(r, 0);
        return;
    }

    wev = c->write;
    wev->handler = ngx_tcp_empty_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_tcp_close_session(r, 0);
            return;
        }
    }

    if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_connection_error(c, ngx_socket_errno,
                             ngx_shutdown_socket_n " failed");
        ngx_tcp_close_session(r, 0);
        return;
    }

    if (rev->ready) {
        ngx_tcp_lingering_close_handler(rev);
    }
}


static void
ngx_tcp_lingering_close_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_msec_t                 timer;
    ngx_connection_t          *c;
    ngx_tcp_session_t        *r;
    ngx_tcp_core_loc_conf_t  *clcf;
    u_char                     buffer[NGX_TCP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp lingering close handler");

    if (rev->timedout) {
        ngx_tcp_close_session(r, 0);
        return;
    }

    timer = (ngx_msec_t) (r->lingering_time - ngx_time());
    if (timer <= 0) {
        ngx_tcp_close_session(r, 0);
        return;
    }

    do {
        n = c->recv(c, buffer, NGX_TCP_LINGERING_BUFFER_SIZE);

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0, "lingering read: %d", n);

        if (n == NGX_ERROR || n == 0) {
            ngx_tcp_close_session(r, 0);
            return;
        }

    } while (rev->ready);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_close_session(r, 0);
        return;
    }

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);

    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    ngx_add_timer(rev, timer);
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

        if (r == r->main && !r->post_action) {
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


static ngx_int_t
ngx_tcp_post_action(ngx_tcp_session_t *r)
{
    ngx_tcp_core_loc_conf_t  *clcf;

    clcf = ngx_tcp_get_module_loc_conf(r, ngx_tcp_core_module);

    if (clcf->post_action.data == NULL) {
        return NGX_DECLINED;
    }

    if (r->post_action && r->uri_changes == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, r->connection->log, 0,
                   "post action: \"%V\"", &clcf->post_action);

    r->main->count--;

    r->tcp_version = NGX_TCP_VERSION_9;
    r->header_only = 1;
    r->post_action = 1;

    r->read_event_handler = ngx_tcp_block_reading;

    if (clcf->post_action.data[0] == '/') {
        ngx_tcp_internal_redirect(r, &clcf->post_action, NULL);

    } else {
        ngx_tcp_named_location(r, &clcf->post_action);
    }

    return NGX_OK;
}


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

    if (r->count || r->blocked) {
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

    if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
        r->headers_out.status = rc;
    }

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

    r->session_line.len = 0;

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
    char                      *uri_separator;
    u_char                    *p;
    ngx_tcp_upstream_t       *u;
    ngx_tcp_core_srv_conf_t  *cscf;

    cscf = ngx_tcp_get_module_srv_conf(r, ngx_tcp_core_module);

    p = ngx_snprintf(buf, len, ", server: %V", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r->session_line.data == NULL && r->session_start) {
        for (p = r->session_start; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->session_line.len = p - r->session_start;
        r->session_line.data = r->session_start;
    }

    if (r->session_line.len) {
        p = ngx_snprintf(buf, len, ", session: \"%V\"", &r->session_line);
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = ngx_snprintf(buf, len, ", subsession: \"%V\"", &sr->uri);
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (NGX_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = ngx_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
                         &u->schema, u->peer.name,
                         uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = ngx_snprintf(buf, len, ", host: \"%V\"",
                         &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = ngx_snprintf(buf, len, ", referrer: \"%V\"",
                         &r->headers_in.referer->value);
        buf = p;
    }

    return buf;
}

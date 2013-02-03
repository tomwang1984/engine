
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


static void *ngx_tcp_core_create_main_conf(ngx_conf_t *cf);
static void *ngx_tcp_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
//static char *ngx_tcp_core_location(ngx_conf_t *cf, ngx_command_t *cmd,
//    void *conf);
static char *ngx_tcp_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_core_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
//static char *ngx_tcp_log_set_access_log(ngx_conf_t *cf, ngx_command_t *cmd,
  //  void *conf);


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

    { ngx_string("server_names"),
      NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
      ngx_tcp_core_server_name,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },
/*
    { ngx_string("location"),
      NGX_TCP_SRV_CONF|NGX_TCP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_tcp_core_location,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },
*/
    { ngx_string("protocol"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_core_protocol,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("so_keepalive"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
      ngx_tcp_core_keepalive,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, so_keepalive),
      NULL },

    { ngx_string("tcp_nodelay"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, tcp_nodelay),
      NULL },

    { ngx_string("timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, timeout),
      NULL },

    { ngx_string("server_name"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, server_name),
      NULL },

    { ngx_string("resolver"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
      ngx_tcp_core_resolver,
      NGX_TCP_SRV_CONF_OFFSET,
      0,  
      NULL },

    { ngx_string("resolver_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_core_srv_conf_t, resolver_timeout),
      NULL },
/*
    { ngx_string("allow"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_access_rule,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("deny"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_access_rule,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },
*/
    { ngx_string("err_log"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_core_error_log,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },
/*
    { ngx_string("access_log"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_tcp_log_set_access_log,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },
*/
    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_core_module_ctx = {
    NULL,                                  /* protocol */
    NULL,                                  /*preconfig*/
    NULL,                                  /*postconfig*/
    ngx_tcp_core_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_tcp_core_create_srv_conf,          /* create server configuration */
    NULL,            /* merge server configuration */
    NULL,                                  /*create loc server*/
    NULL                                   /*merge loc server*/
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


//static ngx_str_t  ngx_tcp_access_log = ngx_string("logs/tcp_access.log");

static char *
ngx_tcp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                        *rv;
    void                        *mconf;
    ngx_uint_t                   i;
    ngx_conf_t                   pcf;
    ngx_tcp_module_t           *module;
    struct sockaddr_in          *sin;
    ngx_tcp_conf_ctx_t         *ctx, *tcp_ctx;
    ngx_tcp_listen_opt_t        lsopt;
    ngx_tcp_core_srv_conf_t    *cscf, **cscfp;
    ngx_tcp_core_main_conf_t   *cmcf;

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

    /* the server{}'s loc_conf */

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[i]->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->loc_conf[ngx_modules[i]->ctx_index] = mconf;
        }
    }


    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_tcp_core_module.ctx_index];
    cscf->ctx = ctx;


    cmcf = ctx->main_conf[ngx_tcp_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_TCP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == NGX_CONF_OK && !cscf->listen) {
        ngx_memzero(&lsopt, sizeof(ngx_tcp_listen_opt_t));

        sin = &lsopt.u.sockaddr_in;

        sin->sin_family = AF_INET;
#if (NGX_WIN32)
        sin->sin_port = htons(80);
#else
        sin->sin_port = htons((getuid() == 0) ? 80 : 8000);
#endif
        sin->sin_addr.s_addr = INADDR_ANY;

        lsopt.socklen = sizeof(struct sockaddr_in);

        lsopt.backlog = NGX_LISTEN_BACKLOG;
        lsopt.rcvbuf = -1;
        lsopt.sndbuf = -1;
#if (NGX_HAVE_SETFIB)
        lsopt.setfib = -1;
#endif
        lsopt.wildcard = 1;

        (void) ngx_sock_ntop(&lsopt.u.sockaddr, lsopt.addr,
                             NGX_SOCKADDR_STRLEN, 1);

        if (ngx_tcp_add_listen(cf, cscf, &lsopt) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return rv;
}

/*
static char *
ngx_tcp_core_location(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                      *rv;
    u_char                    *mod;
    size_t                     len;
    ngx_str_t                 *value, *name;
    ngx_uint_t                 i;
    ngx_conf_t                 save;
    ngx_tcp_module_t         *module;
    ngx_tcp_conf_ctx_t       *ctx, *pctx;
    ngx_tcp_core_loc_conf_t  *clcf, *pclcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_loc_conf) {
            ctx->loc_conf[ngx_modules[i]->ctx_index] =
                                                   module->create_loc_conf(cf);
            if (ctx->loc_conf[ngx_modules[i]->ctx_index] == NULL) {
                 return NGX_CONF_ERROR;
            }
        }
    }

    clcf = ctx->loc_conf[ngx_tcp_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;

    value = cf->args->elts;

    if (cf->args->nelts == 3) {

        len = value[1].len;
        mod = value[1].data;
        name = &value[2];

        if (len == 1 && mod[0] == '=') {

            clcf->name = *name;
            clcf->exact_match = 1;

        } else if (len == 2 && mod[0] == '^' && mod[1] == '~') {

            clcf->name = *name;
            clcf->noregex = 1;

        } else if (len == 1 && mod[0] == '~') {
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid location modifier \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

    } else {

        name = &value[1];

        if (name->data[0] == '=') {

            clcf->name.len = name->len - 1;
            clcf->name.data = name->data + 1;
            clcf->exact_match = 1;

        } else if (name->data[0] == '^' && name->data[1] == '~') {

            clcf->name.len = name->len - 2;
            clcf->name.data = name->data + 2;
            clcf->noregex = 1;

        } else if (name->data[0] == '~') {

            name->len--;
            name->data++;

            if (name->data[0] == '*') {

                name->len--;
                name->data++;
        } else {

            clcf->name = *name;

            if (name->data[0] == '@') {
                clcf->named = 1;
            }
        }
    }

    pclcf = pctx->loc_conf[ngx_tcp_core_module.ctx_index];

    if (pclcf->name.len) {

        if (pclcf->exact_match) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "location \"%V\" cannot be inside "
                               "the exact location \"%V\"",
                               &clcf->name, &pclcf->name);
            return NGX_CONF_ERROR;
        }

        if (pclcf->named) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "location \"%V\" cannot be inside "
                               "the named location \"%V\"",
                               &clcf->name, &pclcf->name);
            return NGX_CONF_ERROR;
        }

        if (clcf->named) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "named location \"%V\" can be "
                               "on the server level only",
                               &clcf->name);
            return NGX_CONF_ERROR;
        }

        len = pclcf->name.len;

        if (ngx_strncmp(clcf->name.data, pclcf->name.data, len) != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "location \"%V\" is outside location \"%V\"",
                               &clcf->name, &pclcf->name);
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_tcp_add_location(cf, &pclcf->locations, clcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_TCP_LOC_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}
*/
static void *
ngx_tcp_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_tcp_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_tcp_listen_t))
        != NGX_OK)
    {
        return NULL;
    }
/*
    if (ngx_array_init(&cmcf->virtual_servers, cf->pool, 4, 
                       sizeof(ngx_tcp_virtual_server_t)) != NGX_OK)
    {
        return NULL;
    }
*/
    return cmcf;
}


static void *
ngx_tcp_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_core_srv_conf_t  *cscf;
    ngx_tcp_log_srv_conf_t   *lscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->client_large_buffers.num = 0;
     */

    if (ngx_array_init(&cscf->server_names, cf->temp_pool, 4,
                       sizeof(ngx_tcp_server_name_t))
        != NGX_OK)
    {
        return NULL;
    }

    cscf->connection_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->timeout = NGX_CONF_UNSET_MSEC;
    cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    cscf->so_keepalive = NGX_CONF_UNSET;
    cscf->tcp_nodelay = NGX_CONF_UNSET;
    //cscf->resolver = NGX_CONF_UNSET_PTR;
    //cscf->file_name = cf->conf_file->file.name.data;
    //cscf->line = cf->conf_file->line;

    lscf = cscf->access_log = ngx_pcalloc(cf->pool, 
                                          sizeof(ngx_tcp_log_srv_conf_t));
    if (lscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     lscf->logs = NULL;
     */

    lscf->open_file_cache = NGX_CONF_UNSET_PTR;

    return cscf;
}

static char *
ngx_tcp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t *cscf = conf;

    ngx_str_t              *value, size;
    ngx_url_t               u;
    ngx_uint_t              n;
    ngx_tcp_listen_opt_t   lsopt;

    cscf->listen = 1;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;
    u.default_port = 80;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    ngx_memzero(&lsopt, sizeof(ngx_tcp_listen_opt_t));

    ngx_memcpy(&lsopt.u.sockaddr, u.sockaddr, u.socklen);

    lsopt.socklen = u.socklen;
    lsopt.backlog = NGX_LISTEN_BACKLOG;
    lsopt.rcvbuf = -1;
    lsopt.sndbuf = -1;
#if (NGX_HAVE_SETFIB)
    lsopt.setfib = -1;
#endif
    lsopt.wildcard = u.wildcard;

    (void) ngx_sock_ntop(&lsopt.u.sockaddr, lsopt.addr,
                         NGX_SOCKADDR_STRLEN, 1);

    for (n = 2; n < cf->args->nelts; n++) {

        if (ngx_strcmp(value[n].data, "default_server") == 0
            || ngx_strcmp(value[n].data, "default") == 0)
        {
            lsopt.default_server = 1;
            continue;
        }

        if (ngx_strcmp(value[n].data, "bind") == 0) {
            lsopt.set = 1;
            lsopt.bind = 1;
            continue;
        }

#if (NGX_HAVE_SETFIB)
        if (ngx_strncmp(value[n].data, "setfib=", 7) == 0) {
            lsopt.setfib = ngx_atoi(value[n].data + 7, value[n].len - 7);

            if (lsopt.setfib == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid setfib \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }
#endif
        if (ngx_strncmp(value[n].data, "backlog=", 8) == 0) {
            lsopt.backlog = ngx_atoi(value[n].data + 8, value[n].len - 8);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.backlog == NGX_ERROR || lsopt.backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "rcvbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.rcvbuf = ngx_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.rcvbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "sndbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.sndbuf = ngx_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.sndbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "accept_filter=", 14) == 0) {
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            lsopt.accept_filter = (char *) &value[n].data[14];
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "accept filters \"%V\" are not supported "
                               "on this platform, ignored",
                               &value[n]);
#endif
            continue;
        }

        if (ngx_strcmp(value[n].data, "deferred") == 0) {
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            lsopt.deferred_accept = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the deferred accept is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (ngx_strncmp(value[n].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            struct sockaddr  *sa;

            sa = &lsopt.u.sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[n].data[10], "n") == 0) {
                    lsopt.ipv6only = 1;

                } else if (ngx_strcmp(&value[n].data[10], "ff") == 0) {
                    lsopt.ipv6only = 2;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid ipv6only flags \"%s\"",
                                       &value[n].data[9]);
                    return NGX_CONF_ERROR;
                }

                lsopt.set = 1;
                lsopt.bind = 1;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ipv6only is not supported "
                                   "on addr \"%s\", ignored", lsopt.addr);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[n].data, "ssl") == 0) {
#if (NGX_TCP_SSL)
            lsopt.ssl = 1;
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "ngx_tcp_ssl_module");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strncmp(value[n].data, "so_keepalive=", 13) == 0) {

            if (ngx_strcmp(&value[n].data[13], "on") == 0) {
                lsopt.so_keepalive = 1;

            } else if (ngx_strcmp(&value[n].data[13], "off") == 0) {
                lsopt.so_keepalive = 2;

            } else {

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                ngx_str_t   s;

                end = value[n].data + value[n].len;
                s.data = value[n].data + 13;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepidle = ngx_parse_time(&s, 1);
                    if (lsopt.tcp_keepidle == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepintvl = ngx_parse_time(&s, 1);
                    if (lsopt.tcp_keepintvl == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    lsopt.tcp_keepcnt = ngx_atoi(s.data, s.len);
                    if (lsopt.tcp_keepcnt == NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (lsopt.tcp_keepidle == 0 && lsopt.tcp_keepintvl == 0
                    && lsopt.tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                lsopt.so_keepalive = 1;

#else

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NGX_CONF_ERROR;

#endif
            }

            lsopt.set = 1;
            lsopt.bind = 1;

            continue;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[n].data[13]);
            return NGX_CONF_ERROR;
#endif
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[n]);
        return NGX_CONF_ERROR;
    }

    if (ngx_tcp_add_listen(cf, cscf, &lsopt) == NGX_OK) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}


static char *
ngx_tcp_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t *cscf = conf;

    u_char                   ch;
    ngx_str_t               *value;
    ngx_uint_t               i;
    ngx_tcp_server_name_t  *sn;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        ch = value[i].data[0];

        if ((ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
            || (ch == '.' && value[i].len < 2))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "server name \"%V\" is invalid", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strchr(value[i].data, '/')) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "server name \"%V\" has suspicious symbols",
                               &value[i]);
        }

        sn = ngx_array_push(&cscf->server_names);
        if (sn == NULL) {
            return NGX_CONF_ERROR;
        }

        sn->server = cscf;

        if (ngx_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
            sn->name = cf->cycle->hostname;

        } else {
            sn->name = value[i];
        }

        if (value[i].data[0] != '~') {
            ngx_strlow(sn->name.data, sn->name.data, sn->name.len);
            continue;
        }

    }

    return NGX_CONF_OK;
}

static char *
ngx_tcp_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
     ngx_tcp_core_srv_conf_t  *cscf = conf;

     ngx_str_t          *value;
     ngx_uint_t          m; 
     ngx_tcp_module_t   *module;
     value = cf->args->elts;

     for (m = 0; ngx_modules[m]; m++) {
           if (ngx_modules[m]->type != NGX_TCP_MODULE) {
               continue;
           }       
           module = ngx_modules[m]->ctx;

           if (module->protocol
                   && ngx_strcmp(module->protocol->name.data, value[1].data) == 0)          
           {
                cscf->protocol = module->protocol;
                return NGX_CONF_OK;
           }       
     }       
     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                  "unknown protocol \"%V\"", &value[1]);

     return NGX_CONF_ERROR;
}

static char *
ngx_tcp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_loc_conf_t *clcf = conf;

    ngx_str_t  *value, name;

    if (clcf->error_log) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "stderr") == 0) {
        ngx_str_null(&name);

    } else {
        name = value[1];
    }

    clcf->error_log = ngx_log_create(cf->cycle, &name);
    if (clcf->error_log == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        clcf->error_log->log_level = NGX_LOG_ERR;
        return NGX_CONF_OK;
    }

    return ngx_log_set_levels(cf, clcf->error_log);
}


static char *
ngx_tcp_core_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_loc_conf_t *clcf = conf;

    ngx_str_t  *value;

    if (clcf->keepalive_timeout != NGX_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    clcf->keepalive_timeout = ngx_parse_time(&value[1], 0);

    if (clcf->keepalive_timeout == (ngx_msec_t) NGX_ERROR) {
        return "invalid value";
    }

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    clcf->keepalive_header = ngx_parse_time(&value[2], 1);

    if (clcf->keepalive_header == (time_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


static char *
ngx_tcp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_loc_conf_t  *clcf = conf;

    ngx_str_t  *value;

    if (clcf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    clcf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (clcf->resolver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
/*
static char *
ngx_tcp_core_pool_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NGX_MIN_POOL_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           NGX_MIN_POOL_SIZE);
        return NGX_CONF_ERROR;
    }

    if (*sp % NGX_POOL_ALIGNMENT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           NGX_POOL_ALIGNMENT);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
*/

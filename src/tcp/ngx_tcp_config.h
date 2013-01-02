
#ifndef _NGX_TCP_CONFIG_H_INCLUDED_
#define _NGX_TCP_CONFIG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


typedef struct {
    void        **main_conf;
    void        **srv_conf;
    void        **loc_conf;
} ngx_tcp_conf_ctx_t;


typedef struct {
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);

    void       *(*create_main_conf)(ngx_conf_t *cf);
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void       *(*create_srv_conf)(ngx_conf_t *cf);
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);

    void       *(*create_loc_conf)(ngx_conf_t *cf);
    char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_tcp_module_t;


#define NGX_TCP_MODULE           0x50545448   /* "TCP" */

#define NGX_TCP_MAIN_CONF        0x02000000
#define NGX_TCP_SRV_CONF         0x04000000
#define NGX_TCP_LOC_CONF         0x08000000
#define NGX_TCP_UPS_CONF         0x10000000
#define NGX_TCP_SIF_CONF         0x20000000
#define NGX_TCP_LIF_CONF         0x40000000
#define NGX_TCP_LMT_CONF         0x80000000


#define NGX_TCP_MAIN_CONF_OFFSET  offsetof(ngx_tcp_conf_ctx_t, main_conf)
#define NGX_TCP_SRV_CONF_OFFSET   offsetof(ngx_tcp_conf_ctx_t, srv_conf)
#define NGX_TCP_LOC_CONF_OFFSET   offsetof(ngx_tcp_conf_ctx_t, loc_conf)


#define ngx_tcp_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_tcp_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define ngx_tcp_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


#define ngx_tcp_conf_get_module_main_conf(cf, module)                        \
    ((ngx_tcp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_tcp_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_tcp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_tcp_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_tcp_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

#define ngx_tcp_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_tcp_module.index] ?                                 \
        ((ngx_tcp_conf_ctx_t *) cycle->conf_ctx[ngx_tcp_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_TCP_CONFIG_H_INCLUDED_ */

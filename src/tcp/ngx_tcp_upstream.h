
#ifndef _NGX_TCP_UPSTREAM_H_INCLUDED_
#define _NGX_TCP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_tcp.h>


#define NGX_TCP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_TCP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_TCP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_TCP_UPSTREAM_FT_TCP_500        0x00000010
#define NGX_TCP_UPSTREAM_FT_TCP_502        0x00000020
#define NGX_TCP_UPSTREAM_FT_TCP_503        0x00000040
#define NGX_TCP_UPSTREAM_FT_TCP_504        0x00000080
#define NGX_TCP_UPSTREAM_FT_TCP_404        0x00000100
#define NGX_TCP_UPSTREAM_FT_UPDATING        0x00000200
#define NGX_TCP_UPSTREAM_FT_BUSY_LOCK       0x00000400
#define NGX_TCP_UPSTREAM_FT_MAX_WAITING     0x00000800
#define NGX_TCP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_TCP_UPSTREAM_FT_OFF             0x80000000

#define NGX_TCP_UPSTREAM_FT_STATUS          (NGX_TCP_UPSTREAM_FT_TCP_500  \
                                             |NGX_TCP_UPSTREAM_FT_TCP_502  \
                                             |NGX_TCP_UPSTREAM_FT_TCP_503  \
                                             |NGX_TCP_UPSTREAM_FT_TCP_504  \
                                             |NGX_TCP_UPSTREAM_FT_TCP_404)

#define NGX_TCP_UPSTREAM_INVALID_HEADER     40


#define NGX_TCP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_TCP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_TCP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_TCP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_TCP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_TCP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_TCP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_TCP_UPSTREAM_IGN_XA_CHARSET     0x00000100


typedef struct {
    ngx_msec_t                       bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;
    time_t                           response_sec;
    ngx_uint_t                       response_msec;
    off_t                            response_length;

    ngx_str_t                       *peer;
} ngx_tcp_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_tcp_upstream_srv_conf_t */
} ngx_tcp_upstream_main_conf_t;

typedef struct ngx_tcp_upstream_srv_conf_s  ngx_tcp_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_tcp_upstream_init_pt)(ngx_conf_t *cf,
    ngx_tcp_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_tcp_upstream_init_peer_pt)(ngx_tcp_session_t *r,
    ngx_tcp_upstream_srv_conf_t *us);


typedef struct {
    ngx_tcp_upstream_init_pt        init_upstream;
    ngx_tcp_upstream_init_peer_pt   init;
    void                            *data;
} ngx_tcp_upstream_peer_t;


typedef struct {
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;

    unsigned                         down:1;
    unsigned                         backup:1;
} ngx_tcp_upstream_server_t;


#define NGX_TCP_UPSTREAM_CREATE        0x0001
#define NGX_TCP_UPSTREAM_WEIGHT        0x0002
#define NGX_TCP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_TCP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_TCP_UPSTREAM_DOWN          0x0010
#define NGX_TCP_UPSTREAM_BACKUP        0x0020


struct ngx_tcp_upstream_srv_conf_s {
    ngx_tcp_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_tcp_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    in_port_t                        default_port;
};


typedef struct {
    ngx_tcp_upstream_srv_conf_t    *upstream;

    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       timeout;

    size_t                           send_lowat;
    size_t                           buffer_size;

    size_t                           busy_buffers_size;
    size_t                           max_temp_file_size;
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    ngx_bufs_t                       bufs;

    ngx_uint_t                       ignore_headers;
    ngx_uint_t                       next_upstream;
    ngx_uint_t                       store_access;
    ngx_flag_t                       buffering;
    ngx_flag_t                       pass_session_headers;
    ngx_flag_t                       pass_session_body;

    ngx_flag_t                       ignore_client_abort;
    ngx_flag_t                       intercept_errors;
    ngx_flag_t                       cyclic_temp_file;

    ngx_path_t                      *temp_path;

    ngx_hash_t                       hide_headers_hash;
    ngx_array_t                     *hide_headers;
    ngx_array_t                     *pass_headers;

    ngx_addr_t                      *local;

    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

    signed                           store:2;
    unsigned                         intercept_404:1;
    unsigned                         change_buffering:1;

    ngx_str_t                        module;
} ngx_tcp_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_tcp_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_tcp_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_tcp_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;

#if (NGX_TCP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    off_t                            content_length_n;

    ngx_array_t                      cache_control;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_tcp_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    in_addr_t                       *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_tcp_upstream_resolved_t;


typedef void (*ngx_tcp_upstream_handler_pt)(ngx_tcp_session_t *r,
    ngx_tcp_upstream_t *u);


struct ngx_tcp_upstream_s {
    ngx_tcp_upstream_handler_pt     read_event_handler;
    ngx_tcp_upstream_handler_pt     write_event_handler;

    ngx_peer_connection_t            peer;

    ngx_event_pipe_t                *pipe;

    ngx_chain_t                     *request_bufs;

    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

    ngx_tcp_upstream_conf_t        *conf;

    ngx_tcp_upstream_headers_in_t   headers_in;

    ngx_tcp_upstream_resolved_t    *resolved;

    ngx_buf_t                        buffer;
    off_t                            length;

    ngx_chain_t                     *out_bufs;
    ngx_chain_t                     *busy_bufs;
    ngx_chain_t                     *free_bufs;

    ngx_int_t                      (*input_filter_init)(void *data);
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;

    ngx_int_t                      (*create_session)(ngx_tcp_session_t *r);
    ngx_int_t                      (*reinit_session)(ngx_tcp_session_t *r);
    ngx_int_t                      (*process_header)(ngx_tcp_session_t *r);
    void                           (*abort_session)(ngx_tcp_session_t *r);
    void                           (*finalize_session)(ngx_tcp_session_t *r,
                                         ngx_int_t rc);
    ngx_int_t                      (*rewrite_redirect)(ngx_tcp_session_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_tcp_session_t *r,
                                         ngx_table_elt_t *h);

    ngx_msec_t                       timeout;

    ngx_tcp_upstream_state_t       *state;

    ngx_str_t                        method;
    ngx_str_t                        schema;
    ngx_str_t                        uri;

    ngx_tcp_cleanup_pt             *cleanup;

    unsigned                         store:1;
    unsigned                         cacheable:1;
    unsigned                         accel:1;
    unsigned                         ssl:1;
#if (NGX_TCP_CACHE)
    unsigned                         cache_status:3;
#endif

    unsigned                         buffering:1;
    unsigned                         keepalive:1;

    unsigned                         request_sent:1;
    unsigned                         header_sent:1;
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_tcp_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_tcp_upstream_param_t;


ngx_int_t ngx_tcp_upstream_create(ngx_tcp_session_t *r);
void ngx_tcp_upstream_init(ngx_tcp_session_t *r);
ngx_tcp_upstream_srv_conf_t *ngx_tcp_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_tcp_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_tcp_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_tcp_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_tcp_upstream_conf_t *conf, ngx_tcp_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_tcp_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_tcp_upstream_module;
extern ngx_conf_bitmask_t  ngx_tcp_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_tcp_upstream_ignore_headers_masks[];


#endif /* _NGX_TCP_UPSTREAM_H_INCLUDED_ */

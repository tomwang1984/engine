#ifndef _NGX_TCP_CORE_H_INCLUDED_
#define _NGX_TCP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


#define NGX_TCP_AIO_OFF                0
#define NGX_TCP_AIO_ON                 1
#define NGX_TCP_AIO_SENDFILE           2


#define NGX_TCP_SATISFY_ALL            0
#define NGX_TCP_SATISFY_ANY            1


#define NGX_TCP_LINGERING_OFF          0
#define NGX_TCP_LINGERING_ON           1
#define NGX_TCP_LINGERING_ALWAYS       2


#define NGX_TCP_IMS_OFF                0
#define NGX_TCP_IMS_EXACT              1
#define NGX_TCP_IMS_BEFORE             2


#define NGX_TCP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_TCP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_TCP_KEEPALIVE_DISABLE_SAFARI  0x0008

typedef struct ngx_tcp_location_tree_node_s  ngx_tcp_location_tree_node_t;
typedef struct ngx_tcp_core_loc_conf_s  ngx_tcp_core_loc_conf_t;

typedef struct {
    union {
        struct sockaddr        sockaddr;
        struct sockaddr_in     sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6    sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un     sockaddr_un;
#endif
        u_char                 sockaddr_data[NGX_SOCKADDRLEN];
    } u;

    socklen_t                  socklen;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                   ipv6only:2;
#endif
    unsigned                   so_keepalive:2;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t                 deferred_accept;
#endif

    u_char                     addr[NGX_SOCKADDR_STRLEN + 1];
} ngx_tcp_listen_opt_t;


typedef enum {
    NGX_TCP_READ_PHASE = 0,

    NGX_TCP_SERVER_REWRITE_PHASE,

    NGX_TCP_REWRITE_PHASE,

    NGX_TCP_PREACCESS_PHASE,

    NGX_TCP_ACCESS_PHASE,

    NGX_TCP_TRY_FILES_PHASE,
    NGX_TCP_CONTENT_PHASE,

    NGX_TCP_LOG_PHASE
} ngx_tcp_phases;

typedef struct ngx_tcp_phase_handler_s  ngx_tcp_phase_handler_t;

typedef ngx_int_t (*ngx_tcp_phase_handler_pt)(ngx_tcp_session_t *r,
    ngx_tcp_phase_handler_t *ph);

struct ngx_tcp_phase_handler_s {
    ngx_tcp_phase_handler_pt  checker;
    ngx_tcp_handler_pt        handler;
    ngx_uint_t                 next;
};


typedef struct {
    ngx_tcp_phase_handler_t  *handlers;
    ngx_uint_t                 server_rewrite_index;
    ngx_uint_t                 location_rewrite_index;
} ngx_tcp_phase_engine_t;


typedef struct {
    ngx_array_t                handlers;
} ngx_tcp_phase_t;

typedef struct {
    ngx_array_t                servers;         /* ngx_tcp_core_srv_conf_t */

    ngx_tcp_phase_engine_t    phase_engine;

    ngx_hash_t                 headers_in_hash;

    ngx_hash_t                 variables_hash;

    ngx_array_t                variables;       /* ngx_tcp_variable_t */
    ngx_uint_t                 ncaptures;

    ngx_uint_t                 server_names_hash_max_size;
    ngx_uint_t                 server_names_hash_bucket_size;

    ngx_uint_t                 variables_hash_max_size;
    ngx_uint_t                 variables_hash_bucket_size;

    ngx_hash_keys_arrays_t    *variables_keys;

    ngx_array_t               listen;
    ngx_array_t               *ports;

    ngx_uint_t                 try_files;       /* unsigned  try_files:1 */

    ngx_tcp_phase_t           phases[NGX_TCP_LOG_PHASE + 1];
} ngx_tcp_core_main_conf_t;

typedef struct {
    ngx_array_t             *logs;       /* array of ngx_tcp_log_t */

    ngx_open_file_cache_t   *open_file_cache;
    time_t                   open_file_cache_valid;
    ngx_uint_t               open_file_cache_min_uses;

    ngx_uint_t               off;        /* unsigned  off:1 */
} ngx_tcp_log_srv_conf_t;


typedef struct {
    /* array of the ngx_tcp_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    ngx_tcp_conf_ctx_t        *ctx;

    ngx_str_t                   server_name;

    ngx_array_t              locations;

    ngx_tcp_protocol_t      *protocol;

    ngx_msec_t               timeout;
    ngx_msec_t               resolver_timeout;

    ngx_flag_t               so_keepalive;
    ngx_flag_t               tcp_nodelay;

    ngx_tcp_log_srv_conf_t  *access_log;

    size_t                      connection_pool_size;
    size_t                      session_pool_size;
    size_t                      client_header_buffer_size;

    ngx_bufs_t                  large_client_header_buffers;

    ngx_msec_t                  client_header_timeout;

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif


    ngx_tcp_core_loc_conf_t  **named_locations;
} ngx_tcp_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
    /* the default server configuration for this address:port */
    ngx_tcp_core_srv_conf_t  *default_server;

    ngx_tcp_virtual_names_t  *virtual_names;

#if (NGX_TCP_SSL)
    ngx_uint_t                 ssl;   /* unsigned  ssl:1; */
#endif
} ngx_tcp_addr_conf_t;


typedef struct {
    in_addr_t                  addr;
    ngx_tcp_addr_conf_t       conf;
} ngx_tcp_in_addr_t;

typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_tcp_conf_ctx_t     *ctx;

    unsigned                default_port:1;
    unsigned                bind:1;
    unsigned                wildcard:1;
    ngx_tcp_core_srv_conf_t *conf;
} ngx_tcp_listen_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_tcp_addr_conf_t       conf;
} ngx_tcp_in6_addr_t;

#endif


typedef struct {
    /* ngx_tcp_in_addr_t or ngx_tcp_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_tcp_port_t;


typedef struct {
    ngx_int_t                  family;
    in_port_t                  port;
    ngx_array_t                addrs;     /* array of ngx_tcp_conf_addr_t */
} ngx_tcp_conf_port_t;


typedef struct {
    ngx_tcp_listen_opt_t      opt;

    ngx_hash_t                 hash;
    ngx_hash_wildcard_t       *wc_head;
    ngx_hash_wildcard_t       *wc_tail;

#if (NGX_PCRE)
    ngx_uint_t                 nregex;
    ngx_tcp_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    ngx_tcp_core_srv_conf_t  *default_server;
    ngx_array_t                servers;  /* array of ngx_tcp_core_srv_conf_t */
} ngx_tcp_conf_addr_t;


struct ngx_tcp_server_name_s {
    ngx_tcp_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
};


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_str_t                  args;
} ngx_tcp_err_page_t;


typedef struct {
    ngx_array_t               *lengths;
    ngx_array_t               *values;
    ngx_str_t                  name;

    unsigned                   code:10;
    unsigned                   test_dir:1;
} ngx_tcp_try_file_t;


struct ngx_tcp_core_loc_conf_s {
    ngx_str_t     name;          /* location name */


    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;

    ngx_tcp_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_tcp_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    ngx_tcp_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */
    size_t        limit_rate_after;        /* limit_rate_after */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_uint_t    keepalive_sessions;      /* keepalive_sessions */
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    ngx_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    sendfile;                /* sendfile */
#if (NGX_HAVE_FILE_AIO)
    ngx_flag_t    aio;                     /* aio */
#endif
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    log_subsession;          /* log_subsession */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_flag_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */


    ngx_array_t  *error_pages;             /* error_page */
    ngx_tcp_try_file_t    *try_files;     /* try_files */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    ngx_uint_t    open_file_cache_min_uses;
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    ngx_queue_t  *locations;

#if 0
    ngx_tcp_core_loc_conf_t  *prev_location;
#endif
};


typedef struct {
    ngx_queue_t                      queue;
    ngx_tcp_core_loc_conf_t        *exact;
    ngx_tcp_core_loc_conf_t        *inclusive;
    ngx_str_t                       *name;
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_tcp_location_queue_t;


struct ngx_tcp_location_tree_node_s {
    ngx_tcp_location_tree_node_t   *left;
    ngx_tcp_location_tree_node_t   *right;
    ngx_tcp_location_tree_node_t   *tree;

    ngx_tcp_core_loc_conf_t        *exact;
    ngx_tcp_core_loc_conf_t        *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};


void ngx_tcp_core_run_phases(ngx_tcp_session_t *r);
ngx_int_t ngx_tcp_core_generic_phase(ngx_tcp_session_t *r,
    ngx_tcp_phase_handler_t *ph);
ngx_int_t ngx_tcp_core_rewrite_phase(ngx_tcp_session_t *r,
    ngx_tcp_phase_handler_t *ph);
ngx_int_t ngx_tcp_core_find_config_phase(ngx_tcp_session_t *r,
    ngx_tcp_phase_handler_t *ph);
ngx_int_t ngx_tcp_core_post_rewrite_phase(ngx_tcp_session_t *r,
    ngx_tcp_phase_handler_t *ph);
ngx_int_t ngx_tcp_core_access_phase(ngx_tcp_session_t *r,
    ngx_tcp_phase_handler_t *ph);
ngx_int_t ngx_tcp_core_post_access_phase(ngx_tcp_session_t *r,
    ngx_tcp_phase_handler_t *ph);
ngx_int_t ngx_tcp_core_try_files_phase(ngx_tcp_session_t *r,
    ngx_tcp_phase_handler_t *ph);
ngx_int_t ngx_tcp_core_content_phase(ngx_tcp_session_t *r,
    ngx_tcp_phase_handler_t *ph);


void *ngx_tcp_test_content_type(ngx_tcp_session_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_tcp_set_content_type(ngx_tcp_session_t *r);
u_char *ngx_tcp_map_uri_to_path(ngx_tcp_session_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_tcp_auth_basic_user(ngx_tcp_session_t *r);


ngx_int_t ngx_tcp_internal_redirect(ngx_tcp_session_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_tcp_named_location(ngx_tcp_session_t *r, ngx_str_t *name);


ngx_tcp_cleanup_t *ngx_tcp_cleanup_add(ngx_tcp_session_t *r, size_t size);


typedef ngx_int_t (*ngx_tcp_output_header_filter_pt)(ngx_tcp_session_t *r);
typedef ngx_int_t (*ngx_tcp_output_body_filter_pt)
    (ngx_tcp_session_t *r, ngx_chain_t *chain);


ngx_int_t ngx_tcp_output_filter(ngx_tcp_session_t *r, ngx_chain_t *chain);
ngx_int_t ngx_tcp_write_filter(ngx_tcp_session_t *r, ngx_chain_t *chain);


ngx_int_t ngx_tcp_set_disable_symlinks(ngx_tcp_session_t *r,
    ngx_tcp_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);

ngx_int_t ngx_tcp_get_forwarded_addr(ngx_tcp_session_t *r, ngx_addr_t *addr,
    u_char *xff, size_t xfflen, ngx_array_t *proxies, int recursive);


extern ngx_module_t  ngx_tcp_core_module;

extern ngx_uint_t ngx_tcp_max_module;

extern ngx_str_t  ngx_tcp_core_get_method;


#define ngx_tcp_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }
                                                                              \
#define ngx_tcp_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_tcp_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define ngx_tcp_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }


#endif /* _NGX_TCP_CORE_H_INCLUDED_ */

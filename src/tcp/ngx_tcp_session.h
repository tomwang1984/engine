
#ifndef _NGX_TCP_SESSION_H_INCLUDED_
#define _NGX_TCP_SESSION_H_INCLUDED_

#define NGX_TCP_OK                    0
#define NGX_TCP_SESSION_TIME_OUT      1
#define NGX_TCP_CLIENT_CLOSED_SESSION 2
#define NGX_TCP_SPECIAL_RESPONSE      3
#define NGX_TCP_CREATED               4
#define NGX_TCP_NO_CONTENT            5
#define NGX_TCP_CLOSE                 6
#define NGX_TCP_FLUSH                 7
#define NGX_TCP_LAST                  8
#define NGX_TCP_INTERNAL_SERVER_ERROR 9
#define NGX_TCP_NOT_FOUND             10
#define NGX_TCP_BAD_GATEWAY           11
#define NGX_TCP_GATEWAY_TIME_OUT      12


typedef enum {
    NGX_TCP_INITING_SESSION_STATE = 0,
    NGX_TCP_READING_SESSION_STATE,
    NGX_TCP_PROCESS_SESSION_STATE,

    NGX_TCP_CONNECT_UPSTREAM_STATE,
    NGX_TCP_WRITING_UPSTREAM_STATE,
    NGX_TCP_READING_UPSTREAM_STATE,

    NGX_TCP_WRITING_SESSION_STATE,
    NGX_TCP_LINGERING_CLOSE_STATE,
    NGX_TCP_KEEPALIVE_STATE
} ngx_tcp_state_e;

typedef struct ngx_tcp_server_name_s  ngx_tcp_server_name_t;


 typedef struct {
   ngx_tcp_session_t               *session;
 
    ngx_buf_t                       **busy;
    ngx_int_t                         nbusy;
 
    ngx_buf_t                       **free;
    ngx_int_t                         nfree;
} ngx_tcp_connection_t;


typedef struct {
     ngx_hash_combined_t              names;

     ngx_uint_t                       nregex;
     ngx_tcp_server_name_t          *regex;
} ngx_tcp_virtual_names_t;


typedef void (*ngx_tcp_cleanup_pt)(void *data);

typedef struct ngx_tcp_cleanup_s  ngx_tcp_cleanup_t;

struct ngx_tcp_cleanup_s {
    ngx_tcp_cleanup_pt               handler;
    void                             *data;
    ngx_tcp_cleanup_t               *next;
};



typedef ngx_int_t (*ngx_tcp_handler_pt)(ngx_tcp_session_t *r);
typedef void (*ngx_tcp_event_handler_pt)(ngx_tcp_session_t *r);


struct ngx_tcp_session_s {
    uint32_t                          signature;         /* "TCP" */

    ngx_connection_t                 *connection;

    void                            **ctx;
    void                            **main_conf;
    void                            **srv_conf;
    void                            **loc_conf;

    ngx_tcp_upstream_t              *upstream;
    ngx_array_t                      *upstream_states;
                                         /* of ngx_tcp_upstream_state_t */

    ngx_tcp_event_handler_pt         read_event_handler;
    ngx_tcp_event_handler_pt         write_event_handler;

    ngx_pool_t                       *pool;

    ngx_tcp_virtual_names_t         *virtual_names;

    ngx_tcp_connection_t            *tcp_connection;

    ngx_tcp_log_handler_pt           log_handler;

    ngx_tcp_cleanup_t               *cleanup;

    time_t                          start_sec;
    ngx_msec_t                      start_msec;

    off_t                           bytes_read;
    off_t                           bytes_write;
    
    unsigned                        aio:1;
    unsigned                        keepalive:1;
    unsigned                        lingering_close:1;
    unsigned                        tcp_state:4;
    unsigned                        count:8;

    ngx_tcp_session_t               *main;
    ngx_int_t                       discard;
};

#endif /* _NGX_TCP_SESSION_H_INCLUDED_ */

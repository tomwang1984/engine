#ifndef _NGX_TCP_H_INCLUDED_
#define _NGX_TCP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_tcp_session_s     ngx_tcp_session_t;
typedef struct ngx_tcp_upstream_s    ngx_tcp_upstream_t;
typedef struct ngx_tcp_cache_s       ngx_tcp_cache_t;
typedef struct ngx_tcp_file_cache_s  ngx_tcp_file_cache_t;
typedef struct ngx_tcp_log_ctx_s     ngx_tcp_log_ctx_t;

typedef ngx_int_t (*ngx_tcp_header_handler_pt)(ngx_tcp_session_t *r,
	    ngx_table_elt_t *h, ngx_uint_t offset);
typedef u_char *(*ngx_tcp_log_handler_pt)(ngx_tcp_session_t *r,
	    ngx_tcp_session_t *sr, u_char *buf, size_t len);

#include <ngx_tcp_session.h>
#include <ngx_tcp_upstream.h>
#include <ngx_tcp_upstream_round_robin.h>
#include <ngx_tcp_config.h>
#include <ngx_tcp_core_module.h>


struct ngx_tcp_log_ctx_s {
    ngx_connection_t    *connection;
    ngx_tcp_session_t  *session;
    ngx_tcp_session_t  *current_session;
};


typedef struct {
    ngx_uint_t           tcp_version;
    ngx_uint_t           code;
    ngx_uint_t           count;
   u_char              *start;
    u_char              *end;
} ngx_tcp_status_t;


#define ngx_tcp_get_module_ctx(r, module)  (r)->ctx[module.ctx_index]
#define ngx_tcp_set_ctx(r, c, module)      r->ctx[module.ctx_index] = c;


ngx_int_t ngx_tcp_add_location(ngx_conf_t *cf, ngx_queue_t **locations,
	    ngx_tcp_core_loc_conf_t *clcf);
ngx_int_t ngx_tcp_add_listen(ngx_conf_t *cf, ngx_tcp_core_srv_conf_t *cscf,
	    ngx_tcp_listen_opt_t *lsopt);


void ngx_tcp_init_connection(ngx_connection_t *c);

ngx_int_t ngx_tcp_parse_session_line(ngx_tcp_session_t *r, ngx_buf_t *b);
ngx_int_t ngx_tcp_parse_complex_uri(ngx_tcp_session_t *r,
	    ngx_uint_t merge_slashes);
ngx_int_t ngx_tcp_parse_status_line(ngx_tcp_session_t *r, ngx_buf_t *b,
	    ngx_tcp_status_t *status);
ngx_int_t ngx_tcp_parse_unsafe_uri(ngx_tcp_session_t *r, ngx_str_t *uri,
	    ngx_str_t *args, ngx_uint_t *flags);
ngx_int_t ngx_tcp_parse_header_line(ngx_tcp_session_t *r, ngx_buf_t *b,
	    ngx_uint_t allow_underscores);
ngx_int_t ngx_tcp_parse_multi_header_lines(ngx_array_t *headers,
	    ngx_str_t *name, ngx_str_t *value);
ngx_int_t ngx_tcp_arg(ngx_tcp_session_t *r, u_char *name, size_t len,
	    ngx_str_t *value);
void ngx_tcp_split_args(ngx_tcp_session_t *r, ngx_str_t *uri,
	    ngx_str_t *args);


ngx_int_t ngx_tcp_find_server_conf(ngx_tcp_session_t *r);
void ngx_tcp_update_location_config(ngx_tcp_session_t *r);
void ngx_tcp_handler(ngx_tcp_session_t *r);
void ngx_tcp_run_posted_sessions(ngx_connection_t *c);
void ngx_tcp_finalize_session(ngx_tcp_session_t *r, ngx_int_t rc);

void ngx_tcp_empty_handler(ngx_event_t *wev);
void ngx_tcp_session_empty_handler(ngx_tcp_session_t *r);

ngx_int_t ngx_tcp_send_special(ngx_tcp_session_t *r, ngx_uint_t flags);

ngx_int_t ngx_tcp_send_header(ngx_tcp_session_t *r);
ngx_int_t ngx_tcp_special_response_handler(ngx_tcp_session_t *r,
	    ngx_int_t error);
ngx_int_t ngx_tcp_filter_finalize_session(ngx_tcp_session_t *r,
	    ngx_module_t *m, ngx_int_t error);
void ngx_tcp_clean_header(ngx_tcp_session_t *r);


time_t ngx_tcp_parse_time(u_char *value, size_t len);
size_t ngx_tcp_get_time(char *buf, time_t t);



ngx_int_t ngx_tcp_discard_session_body(ngx_tcp_session_t *r);
void ngx_tcp_discarded_session_body_handler(ngx_tcp_session_t *r);
void ngx_tcp_block_reading(ngx_tcp_session_t *r);
void ngx_tcp_test_reading(ngx_tcp_session_t *r);


char *ngx_tcp_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_tcp_merge_types(ngx_conf_t *cf, ngx_array_t **keys,
	    ngx_hash_t *types_hash, ngx_array_t **prev_keys,
	        ngx_hash_t *prev_types_hash, ngx_str_t *default_types);
ngx_int_t ngx_tcp_set_default_types(ngx_conf_t *cf, ngx_array_t **types,
	    ngx_str_t *default_type);


extern ngx_module_t  ngx_tcp_module;

extern ngx_str_t  ngx_tcp_html_default_types[];


extern ngx_tcp_output_header_filter_pt  ngx_tcp_top_header_filter;
extern ngx_tcp_output_body_filter_pt    ngx_tcp_top_body_filter;


#endif /* _NGX_TCP_H_INCLUDED_ */

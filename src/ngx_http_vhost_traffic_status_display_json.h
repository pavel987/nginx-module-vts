
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_DISPLAY_JSON_H_INCLUDED_
#define _NGX_HTTP_VTS_DISPLAY_JSON_H_INCLUDED_


u_char *ngx_http_vhost_traffic_status_display_set_main(
    ngx_http_request_t *r, u_char *buf);
u_char *ngx_http_vhost_traffic_status_display_set_server_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_set_server(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_display_set_filter_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_set_filter(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_display_set_upstream_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_server_t *us,
#if nginx_version > 1007001
    ngx_http_vhost_traffic_status_node_t *vtsn
#else
    ngx_http_vhost_traffic_status_node_t *vtsn, ngx_str_t *name
#endif
    );
u_char *ngx_http_vhost_traffic_status_display_set_upstream_alone(
    ngx_http_request_t *r, u_char *buf, ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_display_set_upstream_group(
    ngx_http_request_t *r, u_char *buf);

#if (NGX_HTTP_CACHE)
u_char *ngx_http_vhost_traffic_status_display_set_cache_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_set_cache(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
#endif

u_char *ngx_http_vhost_traffic_status_display_set(ngx_http_request_t *r,
    u_char *buf);


#endif /* _NGX_HTTP_VTS_DISPLAY_JSON_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */

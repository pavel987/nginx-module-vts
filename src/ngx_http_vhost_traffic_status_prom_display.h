
#ifndef _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_
#define _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_HEADER   "# test\n"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_MAIN  \
    "# HELP nginx_server_connections nginx connections\n" \
    "# TYPE nginx_server_connections gauge\n" \
    "nginx_server_connections{status=\"accepted\"} %uA\n" \
    "nginx_server_connections{status=\"active\"} %uA\n" \
    "nginx_server_connections{status=\"handled\"} %uA\n" \
    "nginx_server_connections{status=\"reading\"} %uA\n" \
    "nginx_server_connections{status=\"requests\"} %uA\n" \
    "nginx_server_connections{status=\"waiting\"} %uA\n" \
    "nginx_server_connections{status=\"writing\"} %uA\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_SERVER \
    "# HELP nginx_server_requests requests counter\n" \
    "# TYPE nginx_server_requests counter\n" \
    "nginx_server_requests{code=\"1xx\",host=\"%V\"} %uA\n" \
    "nginx_server_requests{code=\"2xx\",host=\"%V\"} %uA\n" \
    "nginx_server_requests{code=\"3xx\",host=\"%V\"} %uA\n" \
    "nginx_server_requests{code=\"4xx\",host=\"%V\"} %uA\n" \
    "nginx_server_requests{code=\"5xx\",host=\"%V\"} %uA\n" \
    "nginx_server_requests{code=\"total\",host=\"%V\"} %uA\n" \
    "# HELP nginx_server_bytes request/response bytes\n" \
    "# TYPE nginx_server_bytes counter\n" \
    "nginx_server_bytes{direction=\"in\",host=\"%V\"} %uA\n" \
    "nginx_server_bytes{direction=\"out\",host=\"%V\"} %uA\n" \
    "# HELP nginx_server_requestMsec average of request processing times in milliseconds\n" \
    "# TYPE nginx_server_requestMsec gauge\n" \
    "nginx_server_requestMsec{host=\"%V\"} %M\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_SERVER_CACHE \
    "# HELP nginx_cache_requests cache requests counter\n" \
    "# TYPE nginx_cache_requests counter\n" \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"


u_char *ngx_http_vhost_traffic_status_prom_display_set(ngx_http_request_t *r,
                                                  u_char *buf);
u_char *ngx_http_vhost_traffic_status_prom_display_set_server(
        ngx_http_request_t *r, u_char *buf,
        ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_prom_display_set_server_node(
        ngx_http_request_t *r,
        u_char *buf, ngx_str_t *key,
        ngx_http_vhost_traffic_status_node_t *vtsn);

u_char *ngx_http_vhost_traffic_status_prom_display_set_main(
        ngx_http_request_t *r, u_char *buf);

#endif /* _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_ */

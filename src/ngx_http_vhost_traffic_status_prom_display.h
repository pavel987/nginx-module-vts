
#ifndef _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_
#define _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_HEADER   "# test\n"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_MAIN  \
    "# HELP nginx_server_uptime nginx uptime and server info\n" \
    "# TYPE nginx_server_uptime counter\n" \
    "nginx_server_uptime{hostname=\"%V\",version=\"%s\"} %f\n" \
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

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_FILTER \
    "# HELP nginx_filter_bytes request/response bytes\n" \
    "# TYPE nginx_filter_bytes counter\n" \
    "nginx_filter_bytes{direction=\"in\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_bytes{direction=\"out\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "# HELP nginx_filter_requestMsec average of request processing times in milliseconds\n" \
    "# HELP nginx_filter_requests requests counter\n" \
    "# TYPE nginx_filter_requests counter\n" \
    "nginx_filter_requests{code=\"1xx\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_requests{code=\"2xx\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_requests{code=\"3xx\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_requests{code=\"4xx\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_requests{code=\"5xx\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_requests{code=\"total\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "# TYPE nginx_filter_requestMsec gauge\n" \
    "nginx_filter_requestMsec{filter=\"%V\",filterName=\"%V\"} %uA\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_FILTER_CACHE \
    "# HELP nginx_filter_cache filter cache requests\n" \
    "# TYPE nginx_filter_cache counter\n" \
    "nginx_filter_cache{status=\"miss\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"bypass\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"expired\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"stale\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"updating\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"revalidated\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"hit\",filter=\"%V\",filterName=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"scarce\",filter=\"%V\",filterName=\"%V\"} %uA\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_UPSTREAM "{\"server\":\"%V\","  \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"requestMsec\":%M,"                                                      \
    "\"requestMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"responseMsec\":%M,"                                                     \
    "\"responseMsecs\":{"                                                      \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"weight\":%ui,"                                                          \
    "\"maxFails\":%ui,"                                                        \
    "\"failTimeout\":%T,"                                                      \
    "\"backup\":%s,"                                                           \
    "\"down\":%s,"                                                             \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "}"                                                                        \
    "},"

u_char *ngx_http_vhost_traffic_status_prom_display_set(ngx_http_request_t *r,
                                                  u_char *buf);
u_char *ngx_http_vhost_traffic_status_prom_display_set_server(
        ngx_http_request_t *r, u_char *buf,
        ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_prom_display_set_server_node(
        ngx_http_request_t *r,
        u_char *buf, ngx_str_t *key,
        ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_prom_display_set_filter(
        ngx_http_request_t *r, u_char *buf,
        ngx_rbtree_node_t *node);

u_char *ngx_http_vhost_traffic_status_prom_display_set_upstream_group(
        ngx_http_request_t *r, u_char *buf);

u_char *ngx_http_vhost_traffic_status_prom_display_set_main(
        ngx_http_request_t *r, u_char *buf);

#endif /* _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_ */

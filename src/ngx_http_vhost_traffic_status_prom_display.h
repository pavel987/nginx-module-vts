
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

u_char *ngx_http_vhost_traffic_status_prom_display_set(ngx_http_request_t *r,
                                                  u_char *buf);

u_char *ngx_http_vhost_traffic_status_prom_display_set_main(
        ngx_http_request_t *r, u_char *buf);

#endif /* _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_ */

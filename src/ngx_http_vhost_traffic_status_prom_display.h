
#ifndef _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_
#define _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_HEADER   "# TEST\n"

u_char *ngx_http_vhost_traffic_status_prom_display_set(ngx_http_request_t *r,
                                                  u_char *buf);

#endif /* _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_ */

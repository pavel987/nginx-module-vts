
#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_prom_display.h"
//#include "ngx_http_vhost_traffic_status_shm.h"
//#include "ngx_http_vhost_traffic_status_filter.h"
//#include "ngx_http_vhost_traffic_status_display.h"

u_char *
ngx_http_vhost_traffic_status_prom_display_set(ngx_http_request_t *r,
                                          u_char *buf)
{
//    u_char                                    *o, *s;
//    ngx_rbtree_node_t                         *node;
//    ngx_http_vhost_traffic_status_ctx_t       *ctx;
//    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;
//
//    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
//
//    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);
//
//    node = ctx->rbtree->root;
//
//    /* init stats */
//    ngx_memzero(&vtscf->stats, sizeof(vtscf->stats));
//    ngx_http_vhost_traffic_status_node_time_queue_init(&vtscf->stats.stat_request_times);
//
//    /* main & connections */
//    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);
//
//    buf = ngx_http_vhost_traffic_status_display_set_main(r, buf);
//
//    /* serverZones */
//    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S);
//
//    buf = ngx_http_vhost_traffic_status_display_set_server(r, buf, node);
//
//    buf = ngx_http_vhost_traffic_status_display_set_server_node(r, buf, &vtscf->sum_key,
//                                                                &vtscf->stats);
//
//    buf--;
//    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
//    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
//
//    /* filterZones */
//    o = buf;
//
//    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S);
//
//    s = buf;
//
//    buf = ngx_http_vhost_traffic_status_display_set_filter(r, buf, node);
//
//    if (s == buf) {
//        buf = o;
//
//    } else {
//        buf--;
//        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
//        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
//    }
//
//    /* upstreamZones */
//    o = buf;
//
//    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S);
//
//    s = buf;
//
//    buf = ngx_http_vhost_traffic_status_display_set_upstream_group(r, buf);
//
//    if (s == buf) {
//        buf = o;
//        buf--;
//
//    } else {
//        buf--;
//        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
//    }
//
//#if (NGX_HTTP_CACHE)
//    /* cacheZones */
//    o = buf;
//
//    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
//    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S);
//
//    s = buf;
//
//    buf = ngx_http_vhost_traffic_status_display_set_cache(r, buf, node);
//
//    if (s == buf) {
//        buf = o;
//
//    } else {
//        buf--;
//        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
//    }
//#endif
//
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_HEADER);

    return buf;
}

#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_prom_display.h"
#include "ngx_http_vhost_traffic_status_shm.h"
#include "ngx_http_vhost_traffic_status_filter.h"
//#include "ngx_http_vhost_traffic_status_display.h"

u_char *
ngx_http_vhost_traffic_status_prom_display_set_main(ngx_http_request_t *r,
                                               u_char *buf)
{
    ngx_atomic_int_t                           ap, hn, ac, rq, rd, wr, wa;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;
//    ngx_http_vhost_traffic_status_shm_info_t  *shm_info;
//
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;
    wa = *ngx_stat_waiting;

//    shm_info = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_shm_info_t));
//    if (shm_info == NULL) {
//        return buf;
//    }

//    ngx_http_vhost_traffic_status_shm_info(r, shm_info);

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_MAIN,
                      &ngx_cycle->hostname, NGINX_VERSION, (ngx_current_msec - vtscf->start_msec) / 1000.0,
                      ap, ac, hn, rd, rq, wa, wr
                      );

    return buf;
}

u_char *
ngx_http_vhost_traffic_status_prom_display_set_server(ngx_http_request_t *r,
                                                 u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_str_t                                  key;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_node_t      *vtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            buf = ngx_http_vhost_traffic_status_prom_display_set_server_node(r, buf, &key, vtsn);

            /* calculates the sum */
            vtscf->stats.stat_request_counter +=vtsn->stat_request_counter;
            vtscf->stats.stat_in_bytes += vtsn->stat_in_bytes;
            vtscf->stats.stat_out_bytes += vtsn->stat_out_bytes;
            vtscf->stats.stat_1xx_counter += vtsn->stat_1xx_counter;
            vtscf->stats.stat_2xx_counter += vtsn->stat_2xx_counter;
            vtscf->stats.stat_3xx_counter += vtsn->stat_3xx_counter;
            vtscf->stats.stat_4xx_counter += vtsn->stat_4xx_counter;
            vtscf->stats.stat_5xx_counter += vtsn->stat_5xx_counter;
            ngx_http_vhost_traffic_status_node_time_queue_merge(
                    &vtscf->stats.stat_request_times,
                    &vtsn->stat_request_times, vtscf->average_period);

        }

        buf = ngx_http_vhost_traffic_status_prom_display_set_server(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_prom_display_set_server(r, buf, node->right);
    }

    return buf;
}

u_char *
ngx_http_vhost_traffic_status_prom_display_set_server_node(
        ngx_http_request_t *r,
        u_char *buf, ngx_str_t *key,
        ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_int_t                                  rc;
    ngx_str_t                                  tmp, dst;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    tmp = *key;

    (void) ngx_http_vhost_traffic_status_node_position_key(&tmp, 1);

    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &dst, &tmp);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_server_node::escape_json_pool() failed");
    }

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_SERVER,
                      &dst, vtsn->stat_1xx_counter,
                      &dst, vtsn->stat_2xx_counter,
                      &dst, vtsn->stat_3xx_counter,
                      &dst, vtsn->stat_4xx_counter,
                      &dst, vtsn->stat_5xx_counter,
                      &dst, vtsn->stat_request_counter,
                      &dst, vtsn->stat_in_bytes,
                      &dst, vtsn->stat_out_bytes,
                      &dst, ngx_http_vhost_traffic_status_node_time_queue_average(
                              &vtsn->stat_request_times, vtscf->average_method,
                              vtscf->average_period));

    return buf;
}

u_char *
ngx_http_vhost_traffic_status_prom_display_set_filter(ngx_http_request_t *r,
                                                 u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_str_t                                     key, filter_name;
    ngx_uint_t                                    i, j, n, rc;
    ngx_array_t                                  *filter_keys, *filter_nodes;
    ngx_http_vhost_traffic_status_filter_key_t   *keys;
    ngx_http_vhost_traffic_status_filter_node_t  *nodes;
    ngx_http_vhost_traffic_status_node_t         *vtsn;
    ngx_http_vhost_traffic_status_loc_conf_t     *vtscf;

    /* init array */
    filter_keys = NULL;
    filter_nodes = NULL;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    rc = ngx_http_vhost_traffic_status_filter_get_keys(r, &filter_keys, node);

    if (filter_keys != NULL && rc == NGX_OK) {
        keys = filter_keys->elts;
        n = filter_keys->nelts;

        if (n > 1) {
            ngx_qsort(keys, (size_t) n,
                      sizeof(ngx_http_vhost_traffic_status_filter_key_t),
                      ngx_http_traffic_status_filter_cmp_keys);
        }

        ngx_memzero(&key, sizeof(ngx_str_t));

        for (i = 0; i < n; i++) {
            if (keys[i].key.len == key.len) {
                if (ngx_strncmp(keys[i].key.data, key.data, key.len) == 0) {
                    continue;
                }
            }
            key = keys[i].key;

            rc = ngx_http_vhost_traffic_status_filter_get_nodes(r, &filter_nodes, &key, node);

            if (filter_nodes != NULL && rc == NGX_OK) {

                nodes = filter_nodes->elts;
                for (j = 0; j < filter_nodes->nelts; j++) {
                    vtsn = nodes[j].node;

                    key.data = vtsn->data;
                    key.len = vtsn->len;

                    (void) ngx_http_vhost_traffic_status_node_position_key(&key, 2);

                    filter_name.data = vtsn->data;
                    filter_name.len = vtsn->len;

                    (void) ngx_http_vhost_traffic_status_node_position_key(&filter_name, 1);

                    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_FILTER,
                                      &key, &filter_name, vtsn->stat_in_bytes,
                                      &key, &filter_name, vtsn->stat_out_bytes,
                                      &key, &filter_name, vtsn->stat_1xx_counter,
                                      &key, &filter_name, vtsn->stat_2xx_counter,
                                      &key, &filter_name, vtsn->stat_3xx_counter,
                                      &key, &filter_name, vtsn->stat_4xx_counter,
                                      &key, &filter_name, vtsn->stat_5xx_counter,
                                      &key, &filter_name, vtsn->stat_request_counter,
                                      &key, &filter_name, ngx_http_vhost_traffic_status_node_time_queue_average(
                                    &vtsn->stat_request_times, vtscf->average_method,
                                    vtscf->average_period));

                }

                /* destroy array to prevent duplication */
                if (filter_nodes != NULL) {
                    filter_nodes = NULL;
                }
            }

        }

        /* destroy array */
        for (i = 0; i < n; i++) {
            if (keys[i].key.data != NULL) {
                ngx_pfree(r->pool, keys[i].key.data);
            }
        }
        if (filter_keys != NULL) {
            filter_keys = NULL;
        }
    }

    return buf;
}

u_char *
ngx_http_vhost_traffic_status_prom_display_set(ngx_http_request_t *r,
                                          u_char *buf)
{
//    u_char                                    *o, *s;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;

    /* init stats */
    ngx_memzero(&vtscf->stats, sizeof(vtscf->stats));
    ngx_http_vhost_traffic_status_node_time_queue_init(&vtscf->stats.stat_request_times);

    /* main & connections */

    buf = ngx_http_vhost_traffic_status_prom_display_set_main(r, buf);

    /* serverZones */

    buf = ngx_http_vhost_traffic_status_prom_display_set_server(r, buf, node);

    buf = ngx_http_vhost_traffic_status_prom_display_set_server_node(r, buf, &vtscf->sum_key,
                                                                &vtscf->stats);

    /* filterZones */

    buf = ngx_http_vhost_traffic_status_prom_display_set_filter(r, buf, node);

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
//  buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_HEADER);

    return buf;
}
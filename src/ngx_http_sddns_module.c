/*
 * =====================================================================================
 *
 *       Filename:  ngx_sddns_module.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  01/30/2017 05:40:01 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef DDEBUG
#define DDEBUG 1 
#endif
#include "ddebug.h"
#include <math.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include "ngx_http_sddns_module.h"
#include <curl/curl.h>
#include <gmp.h>


static ngx_str_t ORIGIN_HEADER = ngx_string("origin");

static ngx_command_t  ngx_http_sddns_commands[] = {
    { ngx_string("sddns"),
      NGX_HTTP_SRV_CONF|NGX_CONF_NOARGS,
      ngx_http_sddns,
	  0,
	  0,
      NULL },
    { ngx_string("sddns_controller_host"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, controller_host),
      NULL },
    { ngx_string("sddns_controller_port"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, controller_port),
      NULL },

    { ngx_string("sddns_controller_join_url"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      //NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, controller_join_url),
      //offsetof(ngx_http_sddns_main_conf_t, controller_join_url),
      NULL },

    { ngx_string("sddns_enc_secret"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, enc_secret),
      NULL },
    { ngx_string("sddns_sign_secret"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, sign_secret),
      NULL },
    { ngx_string("sddns_cookie_name"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, cookie_name),
      NULL },
    { ngx_string("sddns_cookie_domain"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, cookie_domain),
      NULL },
    { ngx_string("sddns_cookie_expire"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, cookie_expire),
      NULL },
	/*  If the app is using JS then we need to inject JS so ajax calls are made to the changing domain 
    { ngx_string("sddns_js_support"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, cookie_name),
      NULL },
	  */

      ngx_null_command
};

static ngx_http_module_t  ngx_http_sddns_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_sddns_init,					               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_sddns_create_srv_conf,            /* create server configuration */
    ngx_http_sddns_merge_srv_conf,            /* merge server configuration */

    NULL,              						/* create location configuration */
    NULL				                	/* merge location configuration */
};


ngx_module_t  ngx_http_sddns_module = {
    NGX_MODULE_V1,
    &ngx_http_sddns_module_ctx,       /* module context */
    ngx_http_sddns_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,//ngx_http_sddns_module_init,            /* init module */
	NULL,									/* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
/*  
ngx_int_t 
ngx_http_sddns_module_init(ngx_cycle_t *cycle) {
	ngx_http_sddns_main_conf_t *conf;
	conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_sddns_module);
	dd("Controller Join %s", conf->controller_join_url.data);
	if (!ngx_http_sddns_join(conf->controller_join_url)){
		return NGX_ERROR;
	}
	dd("Joined SDDNS");
	return NGX_OK;
}
*/

static void *
ngx_http_sddns_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_sddns_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sddns_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "SDDNS srv conf");

	conf->cookie_expire = NGX_CONF_UNSET;
	conf->allowed = ngx_list_create(cf->pool, 10, sizeof(ngx_http_sddns_client_node_t));
	conf->pool = cf->pool;

    return conf;
}

static char *
ngx_http_sddns_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_sddns_srv_conf_t *prev = parent;
	ngx_http_sddns_srv_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->cookie_name, prev->cookie_name, "");
	ngx_conf_merge_value(conf->cookie_expire, prev->cookie_expire, 0);
  
	dd("Controller Join %s", conf->controller_join_url.data);
	if (!ngx_http_sddns_join(conf->controller_join_url)){
		return NGX_CONF_ERROR;
	}
	dd("Joined SDDNS");

	return NGX_CONF_OK;
}

static char *
ngx_http_sddns(ngx_conf_t *cf, ngx_command_t *comd, void *conf)
{
	return NGX_CONF_OK;
}




static ngx_int_t
ngx_http_sddns_init(ngx_conf_t *cf) 
{
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "INIT SDDNS");

    ngx_http_handler_pt        *h;
    ngx_http_handler_pt        *h1;
    ngx_http_core_main_conf_t  *cmcf;

	

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_sddns_access_handler;

    h1 = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h1 == NULL) {
        return NGX_ERROR;
    }

    *h1 = ngx_http_sddns_content_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_http_sddns_content_handler(ngx_http_request_t *r)
{

	ngx_http_sddns_srv_conf_t 		*sc;
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS content handler");
	
	sc = ngx_http_get_module_srv_conf(r, ngx_http_sddns_module);

	switch(sc->request_type){
		case NGX_HTTP_SDDNS_REQ_CODE_CTRL:
			  return ngx_http_sddns_content_handler_ctrl(r, sc);
		case NGX_HTTP_SDDNS_REQ_CODE_INIT:
			  return ngx_http_sddns_content_handler_init(r, sc);
		default:
			return NGX_DECLINED;
	}

}
static ngx_int_t
ngx_http_sddns_content_handler_ctrl(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc)
{
    ngx_buf_t                      *b;
    ngx_int_t                       rc;
    ngx_chain_t                     out;

    r->headers_out.status = NGX_HTTP_OK;
	r->headers_in.content_length_n = 0;
	ngx_str_set(&r->headers_out.content_type, "text/html");
	ngx_str_set(&r->headers_out.charset, "utf-8");

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    rc = ngx_http_send_header(r);
 
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS send header error");
        return rc;
    }

    b = ngx_create_temp_buf(r->pool, sizeof(CRLF));
    if (b == NULL) {
        return NGX_ERROR;
    }
	b->last = ngx_cpymem(b->last, CRLF,
						 sizeof(CRLF) - 1);

    if (r == r->main) {
        b->last_buf = 1;
    }
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);

}

static ngx_int_t
ngx_http_sddns_content_handler_init(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc)
{
    ngx_buf_t                      *b;
    ngx_chain_t                     out;
    ngx_int_t                       rc;
	ngx_table_elt_t		*host;
    u_char                     *location;
    u_char                     *p;
    size_t                     len;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS content handler init");

	ngx_http_sddns_req_ctx_t *ctx;
	ctx = ngx_http_get_module_ctx(r, ngx_http_sddns_module);

	r->headers_in.content_length_n = 0;
    r->headers_out.status = NGX_HTTP_TEMPORARY_REDIRECT;
	r->keepalive = 0;

	r->header_only = 1;
	r->discard_body = 0;

	ngx_http_clear_content_length(r);
	ngx_str_null(&r->headers_out.content_type);
	r->headers_out.last_modified_time = -1;
	r->headers_out.last_modified = NULL;
	r->headers_out.content_length = 0;
	r->headers_out.content_length_n = 0;
    r->headers_out.content_type_len = 0;

	//ngx_http_clear_location(r);

	r->headers_out.location = ngx_palloc(r->pool, sizeof(ngx_table_elt_t));
	if (r->headers_out.location == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}


	host = r->headers_in.host;
	if (host == NULL){
		return NGX_ERROR;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS host \"%V\"", &host->value);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS token \"%V\"", &ctx->client_token);


	len =  sizeof("http://") - 1;
    len += ctx->client_token.len + 1 + host->value.len + r->uri.len;// + 1; //NULL char
	location = ngx_pcalloc(r->pool, len);
	p = ngx_copy(location, "http://", sizeof("http://") - 1);
	p = ngx_copy(p, ctx->client_token.data, ctx->client_token.len);
	p = ngx_copy(p, ".", sizeof(".") - 1);
	p = ngx_copy(p, host->value.data, host->value.len);
	(void)ngx_copy(p, r->uri.data, r->uri.len);
	//*p = '/';

    ngx_table_elt_t  *set_location;
    set_location = ngx_list_push(&r->headers_out.headers);
    if (set_location == NULL) {
        return NGX_ERROR;
    }

 //   set_location->hash = 0; //this messes it up
    ngx_str_set(&set_location->key, "Location");
    set_location->value.len = len;
    set_location->value.data = location;

	dd("Location: \"%s\"", location);
	//r->headers_out.location->value.len = len;
	//r->headers_out.location->value.data = location;

//	return NGX_HTTP_TEMPORARY_REDIRECT;
//
/*  
	//ngx_str_set(&r->headers_out.content_type, "text/html");
	//ngx_str_set(&r->headers_out.charset, "utf-8");
    //r->headers_out.content_type_len = r->headers_out.content_type.len;
    //r->headers_out.content_type_lowcase = NULL;
*/
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS send header error");
        return rc;
    }
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS content handler init return");
    b = ngx_create_temp_buf(r->pool,  sizeof(CRLF));

    if (b == NULL) {
        return NGX_ERROR;
    }
	b->last = ngx_cpymem(b->last, CRLF,
						 sizeof(CRLF) - 1);

    if (r == r->main) {
        b->last_buf = 1;
    }
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_sddns_access_handler(ngx_http_request_t *r)
{
	ngx_http_sddns_srv_conf_t 		*sc;
	ngx_table_elt_t *		origin_header;


	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Handler");


	sc = ngx_http_get_module_srv_conf(r, ngx_http_sddns_module);
	if (sc == NULL){
		return NGX_ERROR;
	}
	sc->request_type = NGX_HTTP_SDDNS_REQ_CODE_NORMAL;
	/*  
	if (sc->client_token.len > 0){
		ngx_memzero(sc->client_token.data, sc->client_token.len);
		sc->client_token.len = 0;
	}
	*/

	origin_header = ngx_http_sddns_search_headers_in(r, ORIGIN_HEADER.data, ORIGIN_HEADER.len);

	/* Coming from controller */
	if ((origin_header != NULL) && ngx_strcasecmp(origin_header->value.data, sc->controller_host.data) == 0){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Request from controller");
		return ngx_http_sddns_controller_handler(r, sc);

	/* From a client */
	} else {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Request from client");
		return ngx_http_sddns_client_handler(r, sc);
	}

}




static ngx_int_t
ngx_http_sddns_controller_handler(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc)
{

	ngx_str_t						clientid_value;
	ngx_str_t						clientip_value;
	ngx_http_sddns_client_node_t 	*ic;
	ngx_http_sddns_client_node_t 	*cn;


    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "SDDNS parsing arguments");


	/* Make sure the request is authorized */
	if (!ngx_http_sddns_is_authorized(r, sc)){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "SDDNS Not authorized");
		return NGX_HTTP_UNAUTHORIZED; 
	}

	/*  Extract the id and ip, we already know we have both or auth would fail */
    if (r->args.len) {
        if (ngx_http_arg(r, (u_char *) "id", 2, &clientid_value) == NGX_OK) {
			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						  "SDDNS clientid=\"%s\" len=\"%d\"",
						  clientid_value.data, clientid_value.len);


			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						  "SDDNS id=\"%V\"",
						  &clientid_value);
		}
        if (ngx_http_arg(r, (u_char *) "ip", 2, &clientip_value) == NGX_OK) {
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						  "SDDNS ip=\"%V\"",
						  &clientip_value);
		}
	}

	cn = ngx_http_sddns_get_client_by_id(sc, r, sc->allowed, clientid_value);

	if (cn == NULL){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS doesnt exit, insert");

		ic = ngx_http_sddns_insert_client(sc, r, sc->allowed, clientid_value, clientip_value);
		if (ic == NULL){
			return NGX_ERROR;
		}

	} else {
	
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
				"SDDNS this ID is already set to ip=\"%V\"",
				&cn->address);

		if (ngx_strncmp(clientip_value.data, cn->address.data, cn->address.len) != 0){
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Updating IP address");
			ngx_http_sddns_update_client(r, cn, clientip_value);

		} else {
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Record already exists");
		}
	}
	ngx_str_null(&clientid_value);
	ngx_str_null(&clientip_value);
	
	sc->request_type = NGX_HTTP_SDDNS_REQ_CODE_CTRL; 
	return NGX_OK;
}

static ngx_http_sddns_client_node_t * 
ngx_http_sddns_insert_client(ngx_http_sddns_srv_conf_t *sc, ngx_http_request_t *r, ngx_list_t *list, ngx_str_t id, ngx_str_t ip){
    u_char                    *p_id;
    u_char                    *p_ip;
	ngx_http_sddns_client_node_t *elt;

	elt = ngx_list_push(list);
	if (elt == NULL){
		return NULL;
	}

	p_id = ngx_pnalloc(sc->pool, id.len + 1);
	p_ip = ngx_pnalloc(sc->pool, ip.len + 1);

	if (p_id == NULL || p_ip == NULL) {
		return NULL;
	}
	elt->client_id.len = id.len;
	elt->client_id.data = p_id;
	ngx_memcpy(p_id, id.data, id.len+1);

	elt->address.len = ip.len;
	elt->address.data = p_ip;
	ngx_memcpy(p_ip, ip.data, ip.len+1);

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"SDDNS insert id=\"%s\" ip=\"%s\" len=\"%d\"",
			elt->client_id.data, elt->address.data, elt->address.len );

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"SDDNS insert ip=\"%V\"",
			&elt->address);
	return elt;
}

static ngx_http_sddns_client_node_t * 
ngx_http_sddns_update_client(ngx_http_request_t *r, ngx_http_sddns_client_node_t *elt, ngx_str_t ip){
    u_char                    *p;

	p = ngx_pnalloc(r->pool, ip.len + 1);

	if (p == NULL) {
		return NULL;
	}
	ngx_str_null(&elt->address);
	elt->address.len = ip.len;
	elt->address.data = p;
	ngx_memcpy(p, ip.data, ip.len + 1);

	return elt;
}



static ngx_http_sddns_client_node_t*
ngx_http_sddns_get_client_by_id(ngx_http_sddns_srv_conf_t *sc, ngx_http_request_t *r, ngx_list_t *list, ngx_str_t id){

    ngx_uint_t        				i;
    ngx_list_part_t  				*part;
    ngx_http_sddns_client_node_t  	*elts;

    part = &list->part;
    elts = part->elts;

    for (i = 0 ; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            elts = part->elts;
            i = 0;
        }

		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"SDDNS #%d, Search ID=\"%V\" IP=\"%V\"",
			i, &elts[i].client_id, &elts[i].address);

		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"SDDNS #%d Search ID=\"%s\" IP=\"%s\"",
		i, 	elts[i].client_id.data, elts[i].address.data);

		if (ngx_strncmp(id.data, elts[i].client_id.data, id.len) == 0){
			return &elts[i];
		}
    }
	return NULL;
}


static ngx_int_t
ngx_http_sddns_is_authorized(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc){

	ngx_table_elt_t		*auth_header;
	ngx_str_t 			data;
	u_char 				*bin;
	ngx_str_t 			base64, hmac;


	auth_header = r->headers_in.authorization;

	if (auth_header == NULL){

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "SDDNS no auth header");
		return NGX_ERROR;

	} else {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					  "SDDNS authentication=\"%V\"",
					  &auth_header->value);
	}
	

	data = ngx_http_sddns_create_request_string(r);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS signature string=%V",
				  &data);

	base64.len = ngx_base64_encoded_length(32);
	base64.data = ngx_palloc(r->pool, base64.len);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS len \"%d\"",
				  base64.len);

	if (base64.data == NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "SDDNS base64 fail");
		return NGX_ERROR;
	}

	bin = HMAC(EVP_sha256(), sc->sign_secret.data, sc->sign_secret.len, 
			data.data, data.len, NULL, NULL);



	hmac.len = 32;
	hmac.data = bin;

	ngx_encode_base64(&base64, &hmac); 

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS hmac calculated=\"%V\"",
				  &base64);


	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS hmac in header=\"%s\"",
				  auth_header->value.data);

	int i = ngx_strncmp(auth_header->value.data, base64.data, base64.len);
	if (i == 0){
		return 1;
	} else {
		return 0;
	}

}


/*  Copy from AWS http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html */
static ngx_str_t
ngx_http_sddns_create_request_string(ngx_http_request_t *r)
{
	ngx_str_t buff;

	//TODO increase what is signed, ie date
	buff.len =  r->method_name.len + r->args.len;
	buff.data = ngx_palloc(r->pool, buff.len + 1);
	if (buff.data == NULL){
		//return NULL;
	}

	ngx_sprintf(buff.data, "%V%V", &r->method_name,  &r->args);

	return buff;
}

static ngx_int_t
ngx_http_sddns_client_handler(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc)
{

	ngx_http_sddns_client_node_t 	*cn;
	ngx_int_t               		n;  
    ngx_table_elt_t        			**cookies;
	ngx_str_t						cookie_id;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS cookie name \"%V\"",
				  &sc->cookie_name);


	/*  We first need to look to see if this is a normal client request or
	 *  if it is an update being pushed from the server */
	// From the headers get the cookie and place in cookie_id
    n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                                          &sc->cookie_name, &cookie_id );
	//If the cookie cannot be found
    if (n == NGX_DECLINED) {

		return ngx_http_sddns_init_client(r, sc);

    } 

	//TODO check if cookie expire
	cookies = r->headers_in.cookies.elts;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS client cookie \"%V\"",
				  &cookies[n]->value);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS client cookie2 \"%V\"",
				  &cookie_id);

	cn = ngx_http_sddns_get_client_by_id(sc, r, sc->allowed, cookie_id);

	if (!cn){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS not id found");
		return ngx_http_sddns_init_client(r, sc);
	} 


	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS id found");


	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			  "SDDNS ID retrieved \"%V\"",
			  &cn->client_id);
	return NGX_OK;

}

static ngx_int_t
ngx_http_sddns_init_client(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc){

	ngx_str_t						client_id;
	ngx_str_t						client_id_b64;
	ngx_str_t						client_token;
	size_t							len;
	//mpz_t op;
	u_long ip;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS No cookie found");
	ip = ngx_http_sddns_addr(r);
	dd("Clients IP address %lu", ip);

	client_id.len = NGX_HTTP_SDDNS_ID_LEN;
	client_id.data = ngx_pnalloc(r->pool, client_id.len);
	if (client_id.data == NULL){
		return NGX_ERROR;
	}
	ngx_http_sddns_generate_client_id(client_id.data, NGX_HTTP_SDDNS_ID_LEN);

	dd("Session ID len=%zu", client_id.len);
	//print_hex(r->pool, client_id.data, client_id.len);
	u_char *p;
	u_char buf[client_id.len*2];
	//buf = ngx_pnalloc(pool, len);
	p = ngx_hex_dump(buf, client_id.data, client_id.len);
	*p = '\0';
	dd("HEX DUMP \"%s\"", buf);

	//mpz_init(op);
	//mpz_set_ui(op, NGX_HTTP_SDDNS_IV_LEN + NGX_HTTP_SDDNS_TAG_LEN + NGX_HTTP_SDDNS_ID_LEN + 4);
	len =  (int)ceil(NGX_HTTP_SDDNS_IPV4_TOKEN_LEN * 8 / (log(36)/log(2)));//mpz_sizeinbase(op, 36);
	dd("b36 len %zu", len);
	client_token.len = len; //for ipv4
	client_token.data = ngx_pnalloc(r->pool, client_token.len);
	if (client_token.data == NULL){
		return NGX_ERROR;
	}
	dd("Creating token");
	if(ngx_http_sddns_create_token(r->pool, sc->enc_secret, client_id, ip, &client_token) != NGX_OK){
		dd("Token creation failed");
		return NGX_ERROR;
	}


	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS token \"%V\"", &client_token);
	//Encode id
	
	client_id_b64.len = ngx_base64_encoded_length(NGX_HTTP_SDDNS_ID_LEN);
	client_id_b64.data = ngx_palloc(r->pool, client_id_b64.len);
	if (client_id_b64.data == NULL) {
		return NGX_ERROR;
	}
	ngx_encode_base64(&client_id_b64, &client_id); 

	dd("B64 Client ID=\"%s\"", client_id_b64.data);

	dd("Setting cookie");

	//set cookie
	ngx_http_sddns_set_cookie(r, sc, client_id_b64, 0);

	//redirect

	ngx_http_sddns_req_ctx_t  *ctx;
	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sddns_req_ctx_t));
	if (ctx == NULL){
		return NGX_ERROR;
	}
	ngx_http_set_ctx(r, ctx, ngx_http_sddns_module);
	
	ctx->client_token.len = client_token.len;
	ctx->client_token.data = ngx_pnalloc(r->pool, client_token.len);
	if (ctx->client_token.data == NULL){
		return NGX_ERROR;
	}
	ngx_memcpy(ctx->client_token.data, client_token.data, client_token.len);



	sc->request_type = NGX_HTTP_SDDNS_REQ_CODE_INIT;

	return NGX_OK;
}
static ngx_int_t
ngx_http_sddns_set_cookie(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *conf, ngx_str_t cookie_value, int http_only){

    u_char           *cookie, *p;
    size_t            len;
    ngx_table_elt_t  *set_cookie;



    len = conf->cookie_name.len + 1 + cookie_value.len;

    if (conf->cookie_expire) {
		 len += sizeof("; Expires=") - 1 +
			             sizeof("Mon, 01 Sep 1970 00:00:00 GMT") - 1;
    }

	//TODO remember to make HTTP Only
    if (conf->cookie_domain.len) {
		len += sizeof("; Domain=") - 1;
        len += conf->cookie_domain.len;
    }

	//TODO add in Secure
	if (http_only){
		len += sizeof("; HttpOnly") -1;
	}


    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, conf->cookie_name.data, conf->cookie_name.len);
    *p++ = '=';
	p = ngx_copy(p, cookie_value.data, cookie_value.len);

    if (conf->cookie_expire != 0) {
        p = ngx_cpymem(p, "; expires=", sizeof("; expires=") - 1);
        p = ngx_http_cookie_time(p, ngx_time() + conf->cookie_expire);
    }

	if (conf->cookie_domain.len){
		p = ngx_cpymem(p, "; Domain=", sizeof("; Domain=") - 1);
		p = ngx_copy(p, conf->cookie_domain.data, conf->cookie_domain.len);
	}

	if (http_only){
		p = ngx_cpymem(p, "; HttpOnly", sizeof("; HttpOnly") - 1);
	}

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "set cookie: \"%V\"", &set_cookie->value);

	return NGX_OK;
}
static u_long
ngx_http_sddns_addr(ngx_http_request_t *r)
{
 //   size_t                  len;
    ngx_addr_t           addr;
    //ngx_array_t         *xfwd;
    struct sockaddr_in  *sin;
//    u_char                 *p;
//    u_char                  text[NGX_SOCKADDR_STRLEN];


    addr.sockaddr = r->connection->sockaddr;
    addr.socklen = r->connection->socklen;
    //xfwd = &r->headers_in.x_forwarded_for;


#if (NGX_HAVE_INET6)

    if (addr.sockaddr->sa_family == AF_INET6) {
        u_char           *p;
        in_addr_t         inaddr;
        struct in6_addr  *inaddr6;

        inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;

        if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            p = inaddr6->s6_addr;

            inaddr = p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];

            return inaddr;
        }
    }

#endif

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Get Address");
    if (addr.sockaddr->sa_family != AF_INET) {
        return INADDR_NONE;
    }

    sin = (struct sockaddr_in *) addr.sockaddr;

/*  
    len = ngx_sock_ntop(addr.sockaddr, addr.socklen, text,
                        NGX_SOCKADDR_STRLEN, 0);

    if (len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_palloc(r->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

	ip.len = len;
	ip.data = p;
    ngx_memcpy(p, text, len);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS ip address \"%s\"",
				  p);
*/
    return ntohl(sin->sin_addr.s_addr);
	//

}


//https://www.nginx.com/resources/wiki/start/topics/examples/headers_management/
static ngx_table_elt_t *
ngx_http_sddns_search_headers_in(ngx_http_request_t *r, u_char *name, size_t len) {
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_uint_t                  i;

    /*
    Get the first part of the list. There is usual only one part.
    */
    part = &r->headers_in.headers.part;
    h = part->elts;

    /*
    Headers list array may consist of more than one part,
    so loop through all of it
    */
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /*
        Just compare the lengths and then the names case insensitively.
        */
        if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }

        /*
        Ta-da, we got one!
        Note, we'v stop the search at the first matched header
        while more then one header may fit.
        */
        return &h[i];
    }

    /*
    No headers was found
    */
    return NULL;
}

static ngx_int_t
ngx_http_sddns_generate_client_id(u_char * id, int len){

	//s->data = p;
  	if (!RAND_bytes(id, len)){
		return NGX_ERROR;
	}
	return NGX_OK;
}

static ngx_int_t
ngx_http_sddns_create_token(ngx_pool_t *pool, ngx_str_t key, ngx_str_t client_id, u_long ip, ngx_str_t * client_token){
	//TODO mods for ipv6
	ngx_str_t	plaintext;
	u_char		*iv;
	u_char		tag[NGX_HTTP_SDDNS_TAG_LEN];
	u_char		ct[4 + NGX_HTTP_SDDNS_ID_LEN];
	u_char		*p, *p1;
	u_char		*token;
	u_char		ip_buf[4];
	u_char		*token_b36;
	
	iv = ngx_pnalloc(pool, NGX_HTTP_SDDNS_IV_LEN);
	if (iv == NULL){
		return NGX_ERROR;
	}
  	if (!RAND_bytes(iv, NGX_HTTP_SDDNS_IV_LEN)){
		return NGX_ERROR;
	}
	dd("IV");
	print_hex(pool, iv, NGX_HTTP_SDDNS_IV_LEN);

	u_char *s_ip = (u_char *)&ip;
	ngx_memcpy(ip_buf, (u_char *)&ip, 4);

	plaintext.len = 4 + NGX_HTTP_SDDNS_ID_LEN;
	plaintext.data = ngx_palloc(pool, plaintext.len);
	if (plaintext.data == NULL){
		return NGX_ERROR;
	}
	p = ngx_copy(plaintext.data, s_ip, 4);
	ngx_memcpy(p, client_id.data, client_id.len);

	dd("Plaintext");
    print_hex(pool, plaintext.data, plaintext.len);

	ngx_http_sddns_encrypt(plaintext.data, plaintext.len, key.data, iv, NGX_HTTP_SDDNS_IV_LEN, ct, tag, NGX_HTTP_SDDNS_TAG_LEN); 

	dd("Tag");
	print_hex(pool, tag, NGX_HTTP_SDDNS_TAG_LEN);

	dd("Ciphertext");
	print_hex(pool, ct, plaintext.len);

/*  	
	ngx_str_t hexstr = ngx_string("7a");

	ngx_str_t o;
	o.len = ngx_strlen(hexstr.data)/2;
	o.data =  ngx_pnalloc(pool, o.len);
	ngx_http_sddns_hex_to_string(o.data, hexstr.data);
	dd("hex to string \"%s\"", o.data);
	dd("Printing string to hex");
	print_hex(pool, o.data, o.len);
*/
//TODO The client token is wrong, it is the iv+tag+ct, the lengths are wrong	
//
	token = ngx_palloc(pool,  NGX_HTTP_SDDNS_IPV4_TOKEN_LEN);
	if (token == NULL){
		return NGX_ERROR;
	}
	p1 = ngx_copy(token, iv, NGX_HTTP_SDDNS_IV_LEN);
	p1 = ngx_copy(p1, tag, NGX_HTTP_SDDNS_TAG_LEN);
	p1 = ngx_copy(p1, ct, NGX_HTTP_SDDNS_ID_LEN + 4);

	dd("Token");
	print_hex(pool, token, NGX_HTTP_SDDNS_IPV4_TOKEN_LEN);

	token_b36 = ngx_http_sddns_b36_encode(token, NGX_HTTP_SDDNS_IPV4_TOKEN_LEN);
	dd("Token b36 \"%s\"", token_b36 );
	ngx_memcpy(client_token->data, token_b36, client_token->len) ;
	return NGX_OK;
}
/* *
 * size_t len Size of binary data src */
u_char* ngx_http_sddns_b36_encode(u_char *src, size_t len)
{
	u_char *p;
	u_char hex [len*2+1];
	//hex = ngx_pnalloc(pool, len);
	p = ngx_hex_dump(hex, src, len);
	*p = '\0';

	dd("hex \"%s\"", hex);
	mpz_t nr;
	mpz_init(nr);
	mpz_set_str(nr, (char *)hex, 16);
	dd("String \"%s\"", mpz_get_str(NULL, 36, nr));
	return (u_char *)mpz_get_str(NULL, 36, nr);
}

char* ngx_http_sddns_b36_decode(char *src, size_t len){

	mpz_t nr;
	mpz_init(nr);
	mpz_set_str(nr, src, 36);
	//char *hex = mpz_get_str(NULL, 16, nr);
	return NULL;	
}

void ngx_http_sddns_hex_to_string(u_char *dst, u_char *src){
	char * s = (char *)src;
	int i;
	int max = ngx_strlen(s)/2;
	for (i=0; i < max  && isxdigit(*s); i++){
		dst[i]=(u_char)strtol(s, &s, 16);
	}	
	return;
}

/* 
static void
ngx_http_sddns_encode_base64_internal(ngx_str_t *dst, ngx_str_t *src, const u_char *basis,
    ngx_uint_t padding)
{
    u_char         *d, *s;
    size_t          len;

    len = src->len;
    s = src->data;
    d = dst->data;

    while (len > 2) {
		dd("Base64  while %s", d);
        *d++ = basis[(s[0] >> 2) & 0x3f];
        *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis[(s[0] & 3) << 4];
            if (padding) {
                *d++ = '=';
            }

        } else {
            *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis[(s[1] & 0x0f) << 2];
        }

        if (padding) {
            *d++ = '=';
        }
    }

    dst->len = d - dst->data;
}
*/



/*
 * len is length of b
 */
void
print_hex(ngx_pool_t *pool, u_char *bin, int len){

	u_char *p;
	u_char buf[len*2];
	//buf = ngx_pnalloc(pool, len);
	p = ngx_hex_dump(buf, bin, len);
	*p = '\0';
	dd("HEX DUMP \"%s\"", buf);

}

/*  
static ngx_int_t 
ngx_http_sddns_get_rand_bytes(ngx_pool_t *pool, u_char *buf, int len){
    //u_char                    *p;
	//s->len = len;
	buf = ngx_pnalloc(pool, len);
	if (buf == NULL){
		return NGX_ERROR;
	}
	//s->data = p;
  	return  RAND_bytes(buf, len);	
}
*/

int ngx_http_sddns_encrypt(unsigned char *plaintext, int plaintext_len,  unsigned char *key, unsigned char *iv, int iv_len,
	unsigned char *ciphertext, unsigned char *tag, int tag_len)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;


	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		return NGX_ERROR;

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return NGX_ERROR;

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		return NGX_ERROR;

	/*  Set tag length */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL);

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return NGX_ERROR;


	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return NGX_ERROR;
	ciphertext_len = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return NGX_ERROR;
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
		return NGX_ERROR;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int base36encode(const void* data_buf, size_t dataLength, u_char* result, size_t resultSize)
{
   const char base36chars[] = "0123456789abcdefghijklmnopqrstuvwxyz";
   const uint8_t *data = (const uint8_t *)data_buf;
   size_t resultIndex = 0;
   size_t x;
   uint32_t n = 0;
   int padCount = dataLength % 3;
   uint8_t n0, n1, n2, n3;

   /* increment over the length of the string, three characters at a time */
   for (x = 0; x < dataLength; x += 3) 
   {
      /* these three 8-bit (ASCII) characters become one 24-bit number */
      n = ((uint32_t)data[x]) << 16; //parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0
      
      if((x+1) < dataLength)
         n += ((uint32_t)data[x+1]) << 8;//parenthesis needed, compiler depending on flags can do the shifting before conversion to uint32_t, resulting to 0
      
      if((x+2) < dataLength)
         n += data[x+2];

      /* this 24-bit number gets separated into four 6-bit numbers */
      n0 = ((uint8_t)(n >> 18) & 63) % 36;
      n1 = ((uint8_t)(n >> 12) & 63) % 36;
      n2 = ((uint8_t)(n >> 6) & 63) % 36;
      n3 = ((uint8_t)n & 63) % 36;


            
      /*
       * if we have one byte available, then its encoding is spread
       * out over two characters
       */
      if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
      result[resultIndex++] = base36chars[n0];
      if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
      result[resultIndex++] = base36chars[n1];

      /*
       * if we have only two bytes available, then their encoding is
       * spread out over three chars
       */
      if((x+1) < dataLength)
      {
         if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
         result[resultIndex++] = base36chars[n2];
      }

      /*
       * if we have all three bytes available, then their encoding is spread
       * out over four characters
       */
      if((x+2) < dataLength)
      {
         if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
         result[resultIndex++] = base36chars[n3];
      }
   }  

   /*
    * create and add padding that is required if we did not have a multiple of 3
    * number of characters available
    */
   if (padCount > 0) 
   { 
      for (; padCount < 3; padCount++) 
      { 
         if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
         result[resultIndex++] = '=';
      } 
   }
   if(resultIndex >= resultSize) return 1;   /* indicate failure: buffer too small */
   result[resultIndex] = 0;
   return 0;   /* indicate success */
}
#define EQUALS     65
#define INVALID    66

static const unsigned char d[] = {
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66, //0 - 24
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66, 0, 1, //25 - 49 
     2, 3, 4, 5, 6, 7, 8, 9,66,66,66,65,66,66,66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,10,11,12,
    13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66
};

int base36decode (u_char *in, size_t inLen, unsigned char *out, size_t *outLen) { 
    u_char *end = in + inLen;
    u_char iter = 0;
    uint32_t buf = 0;
    size_t len = 0;
    
    while (in < end) {
        unsigned char c = d[*in++];
        
        switch (c) {
        case INVALID:    return 1;   /* invalid input, return error */
        case EQUALS:                 /* pad character, end of data */
            in = end;
            continue;
        default:
            buf = buf << 6 | c;
            iter++; // increment the number of iteration
            /* If the buffer is full, split it into bytes */
            if (iter == 4) {
                if ((len += 3) > *outLen) return 1; /* buffer overflow */
                *(out++) = (buf >> 16) & 255;
                *(out++) = (buf >> 8) & 255;
                *(out++) = buf & 255;
                buf = 0; iter = 0;

            }   
        }
    }
   
    if (iter == 3) {
        if ((len += 2) > *outLen) return 1; /* buffer overflow */
        *(out++) = (buf >> 10) & 255;
        *(out++) = (buf >> 2) & 255;
    }
    else if (iter == 2) {
        if (++len > *outLen) return 1; /* buffer overflow */
        *(out++) = (buf >> 4) & 255;
    }

    *outLen = len; /* modify to reflect the actual output size */
    return 0;
}


int
ngx_http_sddns_join(ngx_str_t join_url){
	CURL *curl;
  	CURLcode res;
	int r = 0;
 
	/* In windows, this will init the winsock stuff */ 
	curl_global_init(CURL_GLOBAL_ALL);

	/* get a curl handle */ 
	curl = curl_easy_init();
	if(curl) {
		//struct curl_slist *chunk = NULL;
		//chunk = curl_slist_append(chunk, "Authorization: example.com");
	    //curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

		/* First set the URL that is about to receive our POST. This URL can
		   just as well be a https:// URL if that is what should receive the
		   data. */ 
		curl_easy_setopt(curl, CURLOPT_URL, join_url.data);
		/* Now specify the POST data */ 
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "ip=1.2.3.4");

		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		/* Check for errors */ 
		if(res == CURLE_OK){
			r = 1;
		} else {
			dd( "Join failed");
		}

		/* always cleanup */ 
		curl_easy_cleanup(curl);
		/*  free the custom headers */ 
	   //curl_slist_free_all(chunk);	
	}
	curl_global_cleanup();
	return r;
}

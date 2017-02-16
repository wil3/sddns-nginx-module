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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "ngx_http_sddns_module.h"


static ngx_str_t ORIGIN_HEADER = ngx_string("origin");

static ngx_command_t  ngx_http_sddns_commands[] = {
    { ngx_string("sddns"),
      NGX_HTTP_SRV_CONF|NGX_CONF_NOARGS,
      ngx_http_sddns,
	  0,
	  0,
      NULL },
    { ngx_string("sddns_controller_name"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, controller_name),
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
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_sddns_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_sddns_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sddns_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "SDDNS srv conf");

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

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS content handler");

    ngx_buf_t                      *b;
    ngx_int_t                       rc;
    ngx_chain_t                     out;
	ngx_http_sddns_srv_conf_t 		*sc;

	
	sc = ngx_http_get_module_srv_conf(r, ngx_http_sddns_module);

	if (!sc->ctrl_request){
        return NGX_DECLINED;
	}

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
ngx_http_sddns_access_handler(ngx_http_request_t *r)
{
	ngx_http_sddns_srv_conf_t 		*sc;
	ngx_table_elt_t *		origin_header;


	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Handler");


	sc = ngx_http_get_module_srv_conf(r, ngx_http_sddns_module);
	if (sc == NULL){
		return NGX_ERROR;
	}
	sc->ctrl_request = 0;

	origin_header = ngx_http_sddns_search_headers_in(r, ORIGIN_HEADER.data, ORIGIN_HEADER.len);

	/* Coming from controller */
	if ((origin_header != NULL) && ngx_strcasecmp(origin_header->value.data, sc->controller_name.data) == 0){
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
	
	sc->ctrl_request = 1;
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
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS No cookie found");
		u_long ip;
		ip = ngx_http_sddns_addr(r);
		dd("Clients IP address %lu", ip);

		ngx_http_sddns_create_client_token(r->pool, sc->enc_secret, ip); 

        return NGX_OK;
    }
	cookies = r->headers_in.cookies.elts;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS client cookie \"%V\"",
				  &cookies[n]->value);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS client cookie2 \"%V\"",
				  &cookie_id);



	cn = ngx_http_sddns_get_client_by_id(sc, r, sc->allowed, cookie_id);

	if (cn){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS id found");


		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS ID retrieved \"%V\"",
				  &cn->client_id);

	//	if (ngx_strncmp(clientip_value.data, cn->address.data, cn->address.len) == 0){


	//	}

	} else {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS not id found");

		return NGX_OK;
	}


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
ngx_http_sddns_create_client_token(ngx_pool_t *pool, ngx_str_t key, u_long ip){
	//ngx_str_t	id;
	//ngx_str_t	iv;
	ngx_str_t	plaintext;
	u_char		*iv;
	u_char		*id;
	int 		id_len = 8;
	int			iv_len = 12;
	int			tag_len = 16;
	u_char		tag[tag_len];
	u_char		*p;
	u_char		ip_buf[32];
	

	dd("Create token");
	/*  Gen session ID */
	id = ngx_pnalloc(pool, id_len);
	if (id == NULL){
		return NGX_ERROR;
	}
	//s->data = p;
  	if (!RAND_bytes(id, id_len)){
		return NGX_ERROR;
	}
	/*  
	if (!ngx_http_sddns_get_rand_bytes(pool, id, 8)){
		return NGX_ERROR;
	}
	*/
	dd("Session ID");
	print_hex(pool, id, id_len/2);

/*  
	if (!ngx_http_sddns_get_rand_bytes(pool, iv, 12)){
		return NGX_ERROR;
	}
	*/

	iv = ngx_pnalloc(pool, iv_len);
	if (iv == NULL){
		return NGX_ERROR;
	}
	//s->data = p;
  	if (!RAND_bytes(iv, iv_len)){
		return NGX_ERROR;
	}


	dd("IV");
	print_hex(pool, iv, iv_len/2);

	u_char *s_ip = (u_char *)&ip;
	ngx_memcpy(ip_buf, (u_char *)&ip, sizeof(ip));

	plaintext.len = 32 + id_len;
	plaintext.data = ngx_palloc(pool, plaintext.len);
	if (plaintext.data == NULL){
		return NGX_ERROR;
	}
	p = ngx_copy(plaintext.data, s_ip, 32);
	ngx_memcpy(p, id, id_len);

	dd("Plaintext");
    print_hex(plaintext);

	u_char		ct[plaintext.len];
	ngx_http_sddns_encrypt(plaintext.data, plaintext.len, key.data, iv, iv_len, ct, tag, tag_len); 


	dd("Ciphertext");
	print_hex(pool, ct, plaintext.len/2);
	return 0;
}

static char *base36enc(u_char *value)
{


	char base36[36] = "0123456789abcdefghijklmnopqrstuvwxyz";
	/* log(2**64) / log(36) = 12.38 => max 13 char + '\0' */

	char buffer[14];
	unsigned int offset = sizeof(buffer);

	buffer[--offset] = '\0';
	do {
		buffer[--offset] = base36[value % 36];
	} while (value /= 36);

	return strdup(&buffer[offset]); // warning: this must be free-d by the user
}

void
print_hex(ngx_pool_t *pool, u_char *b, int len){

	u_char * buf;
	buf = ngx_pnalloc(pool, len);
	(void)ngx_hex_dump(buf, b, len);
	dd("%s", buf);
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

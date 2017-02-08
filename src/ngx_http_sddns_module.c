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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t                  		secret;
	ngx_str_t				   		cookie_name;
	ngx_str_t				   		controller_name;

//	ngx_http_sddns_client_ctx_t		client_ctx;
    ngx_rbtree_t              rbtree;
    ngx_rbtree_node_t         sentinel;
} ngx_http_sddns_srv_conf_t;
/*  
typedef struct {
    ngx_rbtree_t              rbtree;
    ngx_rbtree_node_t         name_sentinel;
} ngx_http_sddns_client_ctx_t;
*/
typedef struct {
    //ngx_rbtree_node_t         node;
	ngx_str_node_t			  sn;
    ngx_queue_t               queue;
    ngx_str_t                 client_id;

    /* PTR: resolved name, A: name to resolve */
    u_char                   *name;
} ngx_http_sddns_client_node_t;

static void *
ngx_http_sddns_create_srv_conf(ngx_conf_t *cf);
static char *
ngx_http_sddns_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static char *
ngx_http_sddns(ngx_conf_t *cf, ngx_command_t *comd, void *conf);
static ngx_int_t
ngx_http_sddns_init(ngx_conf_t *cf); 
static ngx_int_t
ngx_http_sddns_access_handler(ngx_http_request_t *r);
static u_long
ngx_http_sddns_addr(ngx_http_request_t *r);
static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len); 

static ngx_int_t
ngx_http_sddns_client_handler(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc);


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

    { ngx_string("sddns_secret"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, secret),
      NULL },
    { ngx_string("sddns_cookie_name"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, cookie_name),
      NULL },

	/*  ODBC configuration */
    { ngx_string("sddns_db_host"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, secret),
      NULL },
    { ngx_string("sddns_db_port"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, secret),
      NULL },
    { ngx_string("sddns_db_user"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, secret),
      NULL },
    { ngx_string("sddns_db_password"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_sddns_srv_conf_t, secret),
      NULL },



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

	//conf->cookie_name = NGX_CONF_UNSET;

/*  
    ctx->rbtree = ngx_pcalloc(cf->pool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    ctx->sentinel = ngx_pcalloc(cf->pool, sizeof(ngx_rbtree_node_t));
    if (ctx->sentinel == NULL) {
        return NGX_ERROR;
    }
*/
    ngx_rbtree_init(&conf->rbtree, &conf->sentinel,
                    ngx_str_rbtree_insert_value);
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
	/*  
    ngx_shm_zone_t                    *shm_zone;
	//ngx_http_sddns_srv_conf_t *clcf;

	//clcf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_sddns_module);
	//clcf->handler;
	//
	ngx_http_sddns_client_ctx_t	*ctx;


	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_sddns_client_ctx_t));
	if (ctx == NULL){
		return NGX_CONF_ERROR;
	}

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_sddns_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_sddns_init_zone;
    shm_zone->data = ctx;
	*/

	return NGX_CONF_OK;
}
/*  
static ngx_int_t
ngx_http_sddns_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ctx->rbtree = ngx_pcalloc(cf->pool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    ctx->sentinel = ngx_pcalloc(cf->pool, sizeof(ngx_rbtree_node_t));
    if (ctx->sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, ctx->sentinel,
                    ngx_http_sddns_rbtree_insert_value);

}
*/
static ngx_int_t
ngx_http_sddns_init(ngx_conf_t *cf) 
{
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "INIT SDDNS");

    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_sddns_access_handler;

	

    return NGX_OK;
}



static ngx_int_t
ngx_http_sddns_access_handler(ngx_http_request_t *r)
{
	ngx_http_sddns_srv_conf_t 		*sc;
	ngx_table_elt_t *		origin_header;


	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Handler");


	sc = ngx_http_get_module_srv_conf(r, ngx_http_sddns_module);

	origin_header = search_headers_in(r, ORIGIN_HEADER.data, ORIGIN_HEADER.len);
	//ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS after search");

	/* Comming from controller */
	if ((origin_header != NULL) && ngx_strcasecmp(origin_header->value.data, sc->controller_name.data) == 0){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Request from controller");
		return 0;
	/* From a client */
	} else {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS Request from client");
		return ngx_http_sddns_client_handler(r, sc);
	}

}

static ngx_int_t
ngx_http_sddns_client_handler(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc)
{

	ngx_http_sddns_client_node_t 	*cn;
	ngx_int_t               		n;  
    ngx_table_elt_t        			**cookies;
	ngx_str_t						cookie_value;
    uint32_t              			hash;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS cookie name \"%V\"",
				  &sc->cookie_name);




	/*  We first need to look to see if this is a normal client request or
	 *  if it is an update being pushed from the server */
	// From the headers get the cookie and place in cookie_value
    n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                                          &sc->cookie_name, &cookie_value );
	//If the cookie cannot be found
    if (n == NGX_DECLINED) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS return %i", n);
        return 0;
    }
	cookies = r->headers_in.cookies.elts;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS client cookie \"%V\"",
				  &cookies[n]->value);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS client cookie2 \"%V\"",
				  &cookie_value);


    hash = ngx_crc32_long(cookie_value.data, cookie_value.len);
	//node = ngx_http_sddns_lookup_client_secret(cookie_value, hash);
	


//	node = ngx_str_rbtree_lookup(&sc->rbtree, &cookie_value, hash);

	cn = (ngx_http_sddns_client_node_t *) ngx_str_rbtree_lookup(&sc->rbtree, &cookie_value, hash);

	if (cn){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS id found");


		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS ID retrieved \"%V\"",
				  &cn->client_id);
		//return 0;
	} else {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS not id found");
	}

	cn = ngx_palloc(r->pool, sizeof(ngx_http_sddns_client_node_t));
	if (cn == NULL){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SDDNS problem allocating struct");
	}
	
    cn->sn.node.key = hash;
	cn->sn.str.len = cookie_value.len;
	cn->sn.str.data = cookie_value.data;
	cn->client_id = cookie_value;

	ngx_rbtree_insert(&sc->rbtree, &cn->sn.node);

	ngx_http_sddns_addr(r);
	return 0;

}

static u_long
ngx_http_sddns_addr(ngx_http_request_t *r)
{
    size_t                  len;
    ngx_addr_t           addr;
    //ngx_array_t         *xfwd;
    //struct sockaddr_in  *sin;
    u_char                 *p;
    u_char                  text[NGX_SOCKADDR_STRLEN];


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

    //sin = (struct sockaddr_in *) addr.sockaddr;
    len = ngx_sock_ntop(addr.sockaddr, addr.socklen, text,
                        NGX_SOCKADDR_STRLEN, 0);

    if (len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    p = ngx_pnalloc(r->connection->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(p, text, len);

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				  "SDDNS ip address \"%s\"",
				  p);

    //return ntohl(sin->sin_addr.s_addr);
	//

	return INADDR_NONE;
}

/*  
static ngx_resolver_node_t *
ngx_http_sddns_lookup_client_secret(ngx_http_sddns_srv_conf_t *r, ngx_str_t *name, uint32_t hash)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_http_sddns_client_node_t  *rn;

    node = r->rbtree.root;
    sentinel = r->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }


        rn = ngx_resolver_node(node);

        rc = ngx_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }


    return NULL;
}

static void
ngx_http_sddns_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t    **p;
    ngx_http_sddns_client_node_t   *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { // node->key == temp->key 

            rn = ngx_resolver_node(node);
            rn_temp = ngx_resolver_node(temp);

            p = (ngx_memn2cmp(rn->name, rn_temp->name, rn->nlen, rn_temp->nlen)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}
*/

static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len) {
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

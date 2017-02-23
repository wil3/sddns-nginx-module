
#define  NGX_HTTP_SDDNS_TAG_LEN 16
#define  NGX_HTTP_SDDNS_ID_LEN 8
#define  NGX_HTTP_SDDNS_IV_LEN 12

#define  NGX_HTTP_SDDNS_REQ_CODE_NORMAL 0 
#define  NGX_HTTP_SDDNS_REQ_CODE_CTRL 	1 
#define  NGX_HTTP_SDDNS_REQ_CODE_INIT 	2 

typedef struct {
    ngx_str_t                  		enc_secret;
    ngx_str_t                  		sign_secret;
	ngx_str_t				   		cookie_name;
	ngx_str_t				   		cookie_domain;
	time_t								cookie_expire;
	ngx_str_t				   		controller_host;
	int								controller_port;
	int								request_type; 					
	ngx_list_t						*allowed;
	ngx_pool_t                      *pool;
	ngx_str_t				   		controller_join_url;
} ngx_http_sddns_srv_conf_t;
/*  
typedef struct {
} ngx_http_sddns_main_conf_t;
*/
typedef struct {
    ngx_str_t                 client_id;
    ngx_str_t                 address;
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
ngx_http_sddns_search_headers_in(ngx_http_request_t *r, u_char *name, size_t len); 

static ngx_int_t
ngx_http_sddns_client_handler(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc);

static ngx_int_t
ngx_http_sddns_controller_handler(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc);


static ngx_str_t
ngx_http_sddns_create_request_string(ngx_http_request_t *r);

static ngx_int_t
ngx_http_sddns_is_authorized(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc);

static ngx_http_sddns_client_node_t * 
ngx_http_sddns_insert_client(ngx_http_sddns_srv_conf_t *sc, ngx_http_request_t *r, ngx_list_t *list, ngx_str_t id, ngx_str_t ip);

static ngx_http_sddns_client_node_t*
ngx_http_sddns_get_client_by_id(ngx_http_sddns_srv_conf_t *sc, ngx_http_request_t *r, ngx_list_t *list, ngx_str_t id);

static ngx_int_t
ngx_http_sddns_content_handler(ngx_http_request_t *r);

static ngx_http_sddns_client_node_t * 
ngx_http_sddns_update_client(ngx_http_request_t *r, ngx_http_sddns_client_node_t *elt, ngx_str_t ip);

//static int ngx_http_sddns_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
//	int aad_len, unsigned char *key, unsigned char *iv,
//	unsigned char *ciphertext, unsigned char *tag);




static ngx_int_t
ngx_http_sddns_create_token(ngx_pool_t *pool, ngx_str_t key, ngx_str_t client_id, u_long ip, ngx_str_t * client_token);

//static ngx_int_t 
//ngx_http_sddns_get_rand_bytes(ngx_pool_t *pool, u_char *buf, int len);


int ngx_http_sddns_encrypt(unsigned char *plaintext, int plaintext_len,  unsigned char *key, unsigned char *iv, int iv_len,
	unsigned char *ciphertext, unsigned char *tag, int tag_len);


void
print_hex(ngx_pool_t *pool, u_char *b, int len);


//static void base36encode(ngx_str_t *dst, ngx_str_t *src);
//static void
//ngx_http_sddns_encode_base64_internal(ngx_str_t *dst, ngx_str_t *src, const u_char *basis,
 //   ngx_uint_t padding);

u_char* ngx_http_sddns_b36_encode(u_char *src, size_t len);

char* ngx_http_sddns_b36_decode(char *src, size_t len);
void ngx_http_sddns_hex_to_string(u_char *dst, u_char *src);
//int base36encode(const void* data_buf, size_t dataLength, u_char* result, size_t resultSize);
//int base36decode (u_char *in, size_t inLen, unsigned char *out, size_t *outLen); 

int
ngx_http_sddns_join(ngx_str_t join_url);

ngx_int_t ngx_http_sddns_module_init(ngx_cycle_t *cycle); 

static ngx_int_t
ngx_http_sddns_set_cookie(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *conf, ngx_str_t cookie_value, int http_only);

static ngx_int_t
ngx_http_sddns_generate_client_id(u_char * id, int len);

static ngx_int_t
ngx_http_sddns_init_client(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc);

static ngx_int_t
ngx_http_sddns_content_handler_ctrl(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc);
static ngx_int_t
ngx_http_sddns_content_handler_init(ngx_http_request_t *r, ngx_http_sddns_srv_conf_t *sc);

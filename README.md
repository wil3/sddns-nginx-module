# S3B Nginx Module

This is the Nginx module for S3B (a.k.a. SDDNS). Each server must run this module.


# Build

This NGINX  module is complied with NGINX.

1. Download NGINX, PCRE, ZLIB and OpenSSL source code
2. Navigate to Nginx source home directory

./configure --with-pcre=../pcre-8.38 --with-zlib=../zlib-1.2.8
--with-http_ssl_module --with-debug
--add-module=[path-to-code]/nginx-sddns/src

3. make
4. sudo make install
5. Will be installed to /usr/local/nginx
6. Include SDDNS in conf/nginx.conf configuration
7. Run NGINX sbin/nginx


# Configuring nginx.conf
```
    server {
		sddns;
		sddns_controller_host mycontroller.com;
		sddns_enc_secret mysecret;
		sddns_sign_secret mysecret;
		sddns_cookie_name secret;
		sddns_cookie_domain localhost;
		sddns_cookie_expire 1000;
		sddns_controller_join_url "localhost:8080/join";
}
```

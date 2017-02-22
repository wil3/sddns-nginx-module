# sddns-nginx-module

This is the NGINX module for SDDNS. Each server must run this module.


#Build

This NGINX  module is compilied with NGINX.

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

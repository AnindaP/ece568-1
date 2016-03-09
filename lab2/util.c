#include "util.h"

int pem_passwd_cb(char *buf, int size, int rwflag, void *password)
{
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return(strlen(buf));
}

SSL_CTX *initialize_ctx (char *keyfile, char *cafile, char *password)
{
    SSL_METHOD *meth;
    SSL_CTX *ctx;

    /* Global system initialization */
    SSL_library_init();
    SSL_load_error_strings();
    
    /* Set up a SIGPIP handler TODO */

    /* Create server context with SSLv23 method, which can accept hello msgs
     * from SSLv2, SSLv3 and TLSv1 */
    meth = SSLv23_method(); 
    ctx = SSL_CTX_new(meth);
    
    /* Load cert */
    if (!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
	    fprintf(stderr,"can't read certificate file");

    /* Set private key */
    SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *) password);
    if (!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)))
	    fprintf(stderr,"can't read key file");

    /* Load CA */
    if (!(SSL_CTX_load_verify_locations(ctx, cafile, 0)))
	    fprintf(stderr,"can't read CA list");

    return ctx;
}

void ssl_shutdown(SSL* ssl, char* error_string){
  int r = SSL_shutdown(ssl);
  if(!r){
	printf("Sending TCF FIN\n");
        //shutdown(sock, 1);
        r = SSL_shutdown(ssl);
  }

  switch(r){
    case 1://success
      break;
    case 0:
    case -1:
    default:
      printf(error_string);
  }
}

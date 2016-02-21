#ifndef _util_h
#define _util_h
#include <openssl/ssl.h>
#include <openssl/err.h>
#define CA_CERT	"568ca.pem"

#define BUFSIZZ 256
int pem_passwd_cb(char *buf, int size, int rwflag, void *password);
SSL_CTX *initialize_ctx (char *keyfile, char *password);
void ssl_shutdown(SSL* ssl,char* error_string);

#endif

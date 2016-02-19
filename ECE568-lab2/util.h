#ifndef _util_h
#define _util_h

int pem_passwd_cb(char *buf, int size, int rwflag, void *password);
SSL_CTX *initialize_ctx (char *keyfile, char *password);

#endif

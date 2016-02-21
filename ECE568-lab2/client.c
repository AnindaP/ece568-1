#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"

#define HOST "localhost"
#define PORT 8765

/* Server */
#define SERVER_HOST     "Bob's Server"
#define SERVER_EMAIL    "ece568bob@ecf.utoronto.ca"

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

#define CLIENT_KEY      "alice.pem"
#define CLIENT_CERT     "alice.pem"
#define CA_CERT         "568ca.pem"

int check_cert(SSL *ssl) 
{
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];
    char peer_issuer[256];

    if(SSL_get_verify_result(ssl)!=X509_V_OK) {
        printf(FMT_NO_VERIFY);
        return -1;
    }

    /* Check the cert chain */
    peer = SSL_get_peer_certificate(ssl);

    /* Common Name */
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
    if(strcasecmp(peer_CN, SERVER_HOST)){
        printf(FMT_CN_MISMATCH);
        return -1;
    }

    /* Email */
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);
    if(strcasecmp(peer_email, SERVER_EMAIL)){
        printf(FMT_EMAIL_MISMATCH);
        return -1;
    }

    /* Issuer (for printing) */
    X509_NAME_get_text_by_NID(X509_get_issuer_name(peer), NID_commonName, peer_issuer, 256);

    printf(FMT_SERVER_INFO, peer_CN, peer_email, peer_issuer);
    return 0;
}

void server_req_res(SSL* ssl, char* req){
  int req_len = strlen(req);
  int written_len = 0;

  // sending request
  written_len = SSL_write(ssl, req, req_len);
  switch(SSL_get_error(ssl, written_len)){
    case SSL_ERROR_SYSCALL:
      printf(FMT_INCORRECT_CLOSE);
      SSL_free(ssl);
      return;
    case SSL_ERROR_NONE:
      if(req_len != written_len){
         printf("Incomplete write"); 
      }
      break; 
    case SSL_ERROR_ZERO_RETURN:
      ssl_shutdown(ssl, FMT_INCORRECT_CLOSE);
      SSL_free(ssl);
      return;
    default:
      printf("SSL write problem");
      break;
  }

  // reading response
  char buf[BUFSIZZ];
  int r;
  r = SSL_read(ssl, buf, BUFSIZZ);
  switch(SSL_get_error(ssl, r)){
    case SSL_ERROR_NONE:
      break;
    case SSL_ERROR_ZERO_RETURN:
      ssl_shutdown(ssl, FMT_INCORRECT_CLOSE);
      SSL_free(ssl);
      return;
    case SSL_ERROR_SYSCALL:
      printf(FMT_INCORRECT_CLOSE);
      SSL_free(ssl);
      return;
    default:
      printf("SSL read problem");
      ssl_shutdown(ssl, FMT_INCORRECT_CLOSE);
      SSL_free(ssl);
      return;
  }
  buf[r] = '\0';
  printf(FMT_OUTPUT, req, buf);
 
  ssl_shutdown(ssl, FMT_INCORRECT_CLOSE);
  SSL_free(ssl);
  return;
}

int main(int argc, char **argv)
{
  int sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char *secret = "What's the question?";

  /* SSL objects */
  SSL_CTX * ctx;
  BIO * sbio;
  SSL * ssl; 
  
  /* SSL context */
  ctx=initialize_ctx(CLIENT_KEY, "password");
  /* Set sha1 cipher */
  SSL_CTX_set_cipher_list(ctx, "SHA1"); 
  /* Support SSLv3 and TLSv1 only */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");

  /* Connect the SSL socket */
  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE);
  SSL_set_bio(ssl,sbio,sbio);

  /* SSL connection failure */
  if (SSL_connect(ssl) <= 0) {
      //TODO destroy ctx, close sock, print err
      printf(FMT_CONNECT_ERR);
      SSL_CTX_free(ctx);
      close(sock);
      return 1;
  }

  /* Check server cert */
  if (!check_cert(ssl))
      server_req_res(ssl, secret);
  
  close(sock);
  SSL_CTX_free(ctx);
  return 1;
}

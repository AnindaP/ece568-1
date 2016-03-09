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

#include <openssl/ssl.h>

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

#define SERVER_KEY      "bob.pem"
#define SERVER_CERT     "bob.pem"
#define CA_CERT         "568ca.pem"

int check_cert(SSL* ssl)
{
    X509 *peer = SSL_get_peer_certificate(ssl);
    char peer_CN[256];
    char peer_email[256];

    if((SSL_get_verify_result(ssl)!=X509_V_OK)|| (!peer)) {
        printf(FMT_ACCEPT_ERR);
       // ERR_print_errors_fp(stdout);
        return -1;
    }  

    /* Common Name */
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

    /* Email */
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);
   
    printf(FMT_CLIENT_INFO, peer_CN, peer_email);
    return 0;
     
}

void http_serve (SSL *ssl, int s, char* res)
{
    char buf[256];
    int r;

    if(check_cert(ssl))
      return;
    
    //read request
    r = SSL_read(ssl, buf, BUFSIZZ);
    switch(SSL_get_error(ssl, r)){
      case SSL_ERROR_NONE:
        break;
      case SSL_ERROR_ZERO_RETURN:
        ssl_shutdown(ssl, FMT_INCOMPLETE_CLOSE);
        SSL_free(ssl);
        return;
      case SSL_ERROR_SYSCALL:
        printf(FMT_INCOMPLETE_CLOSE);
        SSL_free(ssl);
        return;
      default:
        printf("SSL read problem");
        ssl_shutdown(ssl, FMT_INCOMPLETE_CLOSE);
        SSL_free(ssl);
        return;
    }
    buf[r] = '\0';
    printf(FMT_OUTPUT, buf, res);

    // send response
    int res_len = strlen(res);
    int written_len = 0;

    // sending request
    written_len = SSL_write(ssl, res, res_len);
    switch(SSL_get_error(ssl, written_len)){
      case SSL_ERROR_SYSCALL:
        printf(FMT_INCOMPLETE_CLOSE);
        SSL_free(ssl);
        return;
      case SSL_ERROR_NONE:
        if(res_len != written_len){
           printf("Incomplete write"); 
        }
        break; 
      case SSL_ERROR_ZERO_RETURN:
        break;
      default:
        printf("SSL write problem");
        break;
    }

    ssl_shutdown(ssl, FMT_INCOMPLETE_CLOSE);
    SSL_free(ssl);
    return;   
}

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;

  /* SSL objects */
  SSL_CTX * ctx;
  BIO * sbio;
  SSL * ssl; 
  
  /* SSL context */
  ctx=initialize_ctx(SERVER_KEY, CA_CERT, "password");
  /* Support ciphers in SSLv2, SSLv3 and TLSv1 */
  SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");
  /* Only communicate if client has valid certs */
  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
  
  /*Parse command line arguments*/
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
//TODO format error
	fprintf(stderr,"invalid port number\n");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      int r;

      /* Connect the SSL socket */
      sbio = BIO_new_socket(s, BIO_NOCLOSE);
      ssl = SSL_new(ctx);
      SSL_set_bio(ssl,sbio,sbio);

      /* Server SSL handshake */
      if((r=SSL_accept(ssl)<=0)){
          /* TODO print proper errors here */
        printf(FMT_ACCEPT_ERR);
      }

      // TODO print certs and actually serve http request
      char *answer = "42";
      http_serve(ssl, s, answer);
  
     close(sock);
     close(s);
     return 0;
    }
  }
  SSL_CTX_free(ctx);
  close(sock);
  return 1;
}

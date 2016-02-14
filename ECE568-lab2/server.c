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

int http_serve (SSL *ssl, int s)
{
    char buf[256];
    int r, len;
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
  ctx=initialize_ctx(SERVER_KEY, "password");
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
	fprintf(stderr,"invalid port number");
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
          fprintf(stderr,"ssl err");
      }

      // TODO print certs and actually serve http request
      http_serve(ssl, s);

      /* int len; */
      /* char buf[256]; */
      /* char *answer = "42"; */

      /* len = recv(s, &buf, 255, 0); */
      /* buf[len]= '\0'; */
      /* printf(FMT_OUTPUT, buf, answer); */
      /* send(s, answer, strlen(answer), 0); */
      /* close(sock); */
      /* close(s); */
      return 0; //also close ctx
    }
  }
  
  close(sock);
  return 1; //close ctx
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"


int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];
	char 	padded_secret_hex[20];
	int 	i, prelen, len;

	len = strlen(secret_hex);
	assert (len <= 20);

	prelen = 20 - len;
	for (i = 0; i < prelen; i++)
		padded_secret_hex[i] = '0';
	for ( ; i < 20; i++) 
		padded_secret_hex[i] = secret_hex[i - prelen];
  	padded_secret_hex[i] = '\0';
	
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, padded_secret_hex);
	printf("Secret %s Encoded secret %s\n\n", secret_hex, padded_secret_hex);

	char *encoded_accountName = urlEncode(accountName);
        char *encoded_issuer = urlEncode(issuer);
        char encoded_secret[20];
	//Not a 100% sure what numerical parameters to pass into base32_encode
	int l = base32_encode(secret_hex, 20, encoded_secret, 20);
	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
        char url[200];
	// hotp
	snprintf(url, 200, "otpauth://hotp/%s?issuer=%s&secret=%s&count=1", encoded_accountName, encoded_issuer, padded_secret_hex);
	displayQRcode(url);

	// totp
	snprintf(url, 200, "otpauth://totp/%s?issuer=%s&secret=%s&count=1", encoded_accountName, encoded_issuer, padded_secret_hex);
	displayQRcode(url);

	return (0);
}


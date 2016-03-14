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

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	// hotp
	displayQRcode("otpauth://hotp/gibson?issuer=ECE568&secret=CI2FM6EQCI2FM6EQ&count=1");

	// totp
	displayQRcode("otpauth://totp/gibson?issuer=ECE568&secret=CI2FM6EQCI2FM6EQ&period=30");

	return (0);
}

// TODO: functions that build otpauth strings after encoding/escaping accountname and issuer

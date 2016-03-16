#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "lib/sha1.h"

void create_sha1(char* secret_hex, uint8_t* text, int clen, uint8_t * sha){
//SHA1 generates 20B string
	SHA1_INFO ctx;
	sha1_init(&ctx);
 	char str[50];
	sha1_update(&ctx, secret_hex, strlen(secret_hex));
	// keep calling sha1_update if you have more data to hash...
	sha1_update(&ctx, text, clen);
	sha1_final(&ctx, sha);
        int i = 0;
	printf("\n Text: ");
        for(i =0;i<sizeof(text);i++)
                printf("%d", text[i]);
        printf("\nSHA: 0x");
        for(i =0;i<SHA1_DIGEST_LENGTH;i++)
                printf("%x", sha[i]);

 	return;
}

void prepend_zeros(char* str){
	char temp[7];
	temp[0]='0';
	strcat(temp, str);
	strcpy(str, temp);
}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
	long counter = 1;
	int codeDigits = 6;
	int i;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	//Step1: generate 20B SHA-result
	uint8_t text[sizeof(counter)];
	printf("Secret hex: 0x");
	for(i =0;i<strlen(secret_hex);i++)
		printf("%x", secret_hex[i]);
	printf("\nsizeof(counter) = %d, text=%d, secret_length=%d\n", sizeof(counter), sizeof(text),strlen(secret_hex));
        for( i = sizeof(text)-1; i >= 0 ; i--){
		text[i] = (char)(counter & 0xff);
		counter >>= 8;
	}
	create_sha1(secret_hex,
		text , sizeof(counter), sha);
	

	//Step2: extract 4B dynamic binary code from HMAC

	int offset = sha[SHA1_DIGEST_LENGTH - 1] & 0x0f;
	long binary = ((sha[offset] & 0x7f) << 24)
		| ((sha[offset + 1] & 0xff) << 16)
		| ((sha[offset + 2] & 0xff) << 8)
		| ( sha[offset + 3] & 0xff);
	printf("\nbinary = %li", binary);
	long otp = binary % 1000000;
	printf("\notp = %li", otp);
	char otp_str[7];
	sprintf(otp_str, "%d", otp);
	while(strlen(otp_str) < 6)		
		prepend_zeros(otp_str);
	printf("\n calculated HOTP = %s", otp_str);
	if(strcmp(HOTP_string, otp_str)==0)
		return 1;
	else return 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	return (0);
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}

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

uint8_t hexstr_to_hex(char c) {
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
}

static int 
validateOTP(char * secret_hex, uint8_t * data, char * HOTP_string)
{
	int i, j;
    uint8_t ipad[65]; /* inner padding - key XORd with ipad */
    uint8_t opad[65]; /* outer padding - key XORd with opad */
    int s_len = strlen(secret_hex);
    int k_len = s_len/2;
    uint8_t key[k_len];
    SHA1_INFO ctx;


    // Convert string of 20 hex characters to an array of 
    // bytes (two hex chars correspond to 1 uint8_t value)
    for (i = 0, j = 0; i < s_len; i+=2, j++) {
        key[j] = hexstr_to_hex(secret_hex[i]) * 16 + hexstr_to_hex(secret_hex[i + 1]);
    

    /* The HMAC_SHA1 transform looks like: */
    /* SHA1(K XOR opad, SHA1(K XOR ipad, text)) */
    /* where K is an n byte key */
    /* ipad is the byte 0x36 repeated 64 times */
    /* opad is the byte 0x5c repeated 64 times */
    /* and text is the data being protected */ 

    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memcpy(ipad, key, k_len);
    memcpy(opad, key, k_len);

    /* XOR key with ipad and opad values */
    for (i = 0; i < 64; i++) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

	
    // Compute inner hash
    uint8_t ihmac[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, 64);
    sha1_update(&ctx, data, sizeof(data));
    sha1_final(&ctx, ihmac);

    // Compute inner hash
    uint8_t hmac[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, ihmac, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, hmac);

	// Extract 4B dynamic binary code from HMAC
	int offset = hmac[SHA1_DIGEST_LENGTH - 1] & 0x0f;
	long binary = ((hmac[offset] & 0x7f) << 24)
		| ((hmac[offset + 1] & 0xff) << 16)
		| ((hmac[offset + 2] & 0xff) << 8)
		| ( hmac[offset + 3] & 0xff);

	long otp = binary % 1000000;
	char otp_str[7];
	sprintf(otp_str, "%ld", otp);
	while(strlen(otp_str) < 6)		
		prepend_zeros(otp_str);

	printf("\nbinary = %li", binary);
	printf("\notp = %li", otp);
	printf("\n calculated HOTP = %s", otp_str);

	if(strcmp(HOTP_string, otp_str)==0)
		return 1;
	else return 0;

}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    // 8-byte counter array
    int i;
	long counter = 1;
	uint8_t text[sizeof(counter)];
    for( i = sizeof(text)-1; i >= 0 ; i--){
		text[i] = (char)(counter & 0xff);
		counter >>= 8;
	}
    return validateOTP(secret_hex, text, HOTP_string);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    int t = ((int)time(NULL))/30; // period = 30

    int i;
    uint8_t timer[8]; 
    for( i = 7; i >= 0 ; i--){
        timer[i] = t & 0xff;
        t >>= 8;
    }
    return validateOTP(secret_hex, timer, TOTP_string);
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

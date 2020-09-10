#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct __rc4 {
	int S[256]; 
	int K[256];
	int i;
	int j;
}RC4;

void rc4_stream_setup(char *key, RC4 *rc4) {
	int keysz = strlen(key);
	int i = 0, j = 0, tmp = 0;

	for (i = 0; i < 255; i++) {
		rc4->S[i] = i;
		rc4->K[i] = key[j++ % keysz];	
	}

	for (i = 0; i < 255; i++) {
		j = (j + rc4->S[i] + (int)rc4->K[i]) % 256;
		
		tmp = rc4->S[i];
		rc4->S[i] = rc4->S[j];
		rc4->S[j] = tmp;
	}
}

char rc4_get_byte_stream(RC4 *rc4) {
	int tmp = 0;
	
	rc4->i = (rc4->i +1) % 256;
	rc4->j = (rc4->j + rc4->S[rc4->i]) % 256;

	tmp = rc4->S[rc4->i];
	rc4->S[rc4->i] = rc4->S[rc4->j];
	rc4->S[rc4->j] = tmp;

	int t = (rc4->S[rc4->i] + rc4->S[rc4->j]) % 256;
	char *sbyte = (char*)(&rc4->S[t]);
	
	return sbyte[0];
}	


char *rc4_crypt(char *data, RC4 *rc4) {
	char xor_byte;
	int i, data_len = strlen(data);

	for (i=0; i < data_len; i++) {
		xor_byte = rc4_get_byte_stream(rc4);
		data[i] ^= xor_byte;
	}
	return data;
}

/*
int main() {
	char key[] = "abcdefg";
	char data[] = "hello_world";
	
	RC4 *rc4_encrypt = (RC4*)calloc(1, sizeof(RC4));
	RC4 *rc4_decrypt = (RC4*)calloc(1, sizeof(RC4));

	rc4_stream_setup(key, rc4_encrypt);
	rc4_stream_setup(key, rc4_decrypt);
	
	printf ("Original data is %s\n", data);
	
	char *data_encrypted = rc4_crypt (data, rc4_encrypt);
	printf("The encrypted data is %s\n", data_encrypted);

	char *data_decrypted = rc4_crypt (data, rc4_decrypt);
	printf ("The decrypted data is %s\n", data_decrypted);
	
	free(rc4_encrypt);
	free(rc4_decrypt);

	return 0;
	
}
*/

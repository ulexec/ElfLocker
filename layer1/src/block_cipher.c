#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/anti_debugging.h"
#include "../include/rc4_test.h"
#include "../include/crc32_test.h"

#define BLOCKSIZE (16 * 1112)
#define A_RC4 		0x0
#define A_RC5 		0x1
#define A_AES 		0x2
#define A_3DES 		0x3
#define A_SERPENT 	0x4

typedef void (*generic_encrypt_decrypt)(char *, char *, int);

//char str[] = "Rnremitting scientific effort over the past 400 years has yielded an astonishing amount of information about the world we inhabit. By rights we ought to be very impressed and extremely interested. Unfortunately many of us simply aren't. Far from attracting the best candidates, science is proving a less and less popular subject in schools. And, with a few notable exceptions, popular books on scientific topics are a rare bird in the bestseller lists. Bill Bryson, the travel-writing phenomenon, thinks he knows what has gone wrong.";

void get_num_of_chunks(int text_size, int *nchunks, int *align){	
	*nchunks = text_size/BLOCKSIZE;
	*align = text_size - BLOCKSIZE * *nchunks;
}

/*
	ALGORITHM TABLE:
		0000 RC4
		0001 RC5
		0010 3DES
		0011 AES
		0100 SERPENT
*/

generic_encrypt_decrypt *ENCRYPTION_ARRAY[5] = {
	(generic_encrypt_decrypt*)RC4, // 0000
	(generic_encrypt_decrypt*)RC4, // 0001
	(generic_encrypt_decrypt*)RC4, // 0010
	(generic_encrypt_decrypt*)RC4, // 0011
	(generic_encrypt_decrypt*)RC4  // 0100
	};

void encrypt_decrypt_block(char *chunk, int chunk_size, char *key, void (*f)(char*, char*, int)){
	(*f)(key, chunk, chunk_size);
}

void get_next_key(char *data, int size, char *key){
	for(int i = 0; i < 4; i++) {
		int crc = xcrc32(data, size);
		memcpy(key + i * 4, &crc, sizeof(int));
	}

}

/*
Returns a constant that represents a encryption algorithm
The returned algorithm depends on the last crc byte value
*/

int get_function_for_encrypting(char* crc){
	switch (*crc & 0xF) {
		case A_RC4:
			return A_RC4;
		case A_RC5:
			return A_RC5;
		case A_AES:
			return A_AES;
		case A_3DES:
			return A_3DES;
		case A_SERPENT:
			return A_SERPENT;
		default:
			return A_RC4;
	};	
}

void encrypt_data(int total_size, char *plain_data){
	int nchunks, align;
	int i;
	char key[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41";
	get_num_of_chunks(total_size, &nchunks, &align);


	for (i = 0; i < nchunks; i++) {
		// Encrpt chunk with selected encrypt algorithm and gotten key
		encrypt_decrypt_block(plain_data + i * BLOCKSIZE, 
				      BLOCKSIZE, 
                                      key, 
                                      (void (*)(char *, char *, int))ENCRYPTION_ARRAY[get_function_for_encrypting(key)]);
		/* 
		Get key from the last encrypted chunk.
		This key will be used to encrypt the next chunk.
		key = crc(encrypted-chunk).crc(encrypted-chunk)
		*/
		get_next_key(plain_data + i * BLOCKSIZE, BLOCKSIZE, key);
	}

	/*
	In this case, we are going to use always an encryption algorithm which encrypts in stream mode,
	because when there is align means the block is not multiple of BLOCKSIZE so (not in all cases) it is not
	valid to be encrypted with encryption algorithms which uses blocks for encryption.
	RC4, RC5, SERPENT... are possible candidates.
	*/
	if (align) {

		encrypt_decrypt_block(plain_data + i * BLOCKSIZE, 
				      align, 
				      key, 
				      (void (*)(char *, char *, int))ENCRYPTION_ARRAY[get_function_for_encrypting(key)]);
	}
}


void decrypt_data(int nchunks, int align, char *encrypted_data){
	char key[16];
	int last_chunk_size = align;


	if (align && nchunks) {
		get_next_key(encrypted_data + (nchunks - 1) * BLOCKSIZE, BLOCKSIZE, key);
		encrypt_decrypt_block(encrypted_data + nchunks * BLOCKSIZE, 
				      align, 
				      key, 
				      (void (*)(char *, char *, int))ENCRYPTION_ARRAY[get_function_for_encrypting(key)]);
		last_chunk_size = BLOCKSIZE;
	}

	for (int i = nchunks - 1 ; i >= 1; i--) {
		get_next_key(encrypted_data + (i - 1) * BLOCKSIZE, BLOCKSIZE, key);
		encrypt_decrypt_block(encrypted_data + i * BLOCKSIZE, 
				      BLOCKSIZE, 
                                      key, 
                                      (void (*)(char *, char *, int))ENCRYPTION_ARRAY[get_function_for_encrypting(key)]);
	}


	char key1[16] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41";
	encrypt_decrypt_block(encrypted_data + 0 * BLOCKSIZE, 
				      last_chunk_size, 
                      key1, 
                      (void (*)(char *, char *, int))ENCRYPTION_ARRAY[get_function_for_encrypting(key1)]);


}


int encrypt_buff(char *data, int size){

	encrypt_data(size, data);
	return 1;
}


void decrypt_buff(char *data, int size){
	int nchunks = 0;
	int align = 0;

	get_num_of_chunks(size, &nchunks, &align);
	decrypt_data(nchunks, align, data);
}

/*
int main( int argc, char *argv[]) {
	int num_chunks = 0;
	int align = 0;
	int size;
	//int i;

	size = strlen(str); // Viene dado por el size del header
	get_num_of_chunks(size, &num_chunks, &align);

	printf("[+] PLAIN TEXT:\n%s\n\n", str);
	printf("\t[*] BLOCKSIZE: %d, BLOCKS: %d, ALIGN: %d DATALEN: %d\n\n", BLOCKSIZE, num_chunks, align, size);
	encrypt(str, size);
	//printf("\n");
	//printf("[+] CRYPTED TEXT(HEX): \n");
	//for (i = 0; i < size; i++) {
	//	printf("%02hhX ", str[i]);
	//}
	decrypt(str, size);
	//printf("\n");
	printf("[+] DECRYPTED TEXT:\n%s\n", str);
	return 0;
} */


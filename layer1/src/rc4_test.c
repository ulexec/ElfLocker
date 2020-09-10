#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define N 256   // 2^8

void swap(unsigned char *a, unsigned char *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int KSA(char *key, unsigned char *S) {

    int len = 16;
    unsigned int j = 0;

    for(int i = 0; i < N; i++)
        S[i] = i;

    for(int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;

        swap(&S[i], &S[j]);
    }

    return 0;
}

int PRGA(unsigned char *S, char *plaintext, int size) {

    int i = 0;
    int j = 0;

    for(size_t n = 0, len = size; n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];

        plaintext[n] = rnd ^ plaintext[n];

    }

    return 0;
}

int RC4(char *key, char *plaintext, int size) {

    unsigned char S[N];
    KSA(key, S);

    PRGA(S, plaintext, size);

    return 0;
}

//int main(int argc, char *argv[]) {

//    if(argc < 3) {
//        printf("Usage: %s <key> <plaintext>", argv[0]);
//        return -1;
//    }


//    RC4(argv[1], argv[2], strlen(argv[2]));

//    for(size_t i = 0, len = strlen(argv[2]); i < len; i++)
//        printf("%02hhX", argv[2][i]);
//    printf("\n");
//    return 0;
//}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/ptrace.h>
#include <signal.h>
#define __USE_GNU
#include <ucontext.h>
#define N 256   // 2^8

void __attribute__((section(".crypter"))) swap(unsigned char *a, unsigned char *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int  __attribute__((section(".crypter"))) KSA(char *key, int len, unsigned char *S) {
    int j = 0;

    for(int i = 0; i < N; i++)
        S[i] = i;

    for(int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;

        swap(&S[i], &S[j]);
    }

    return 0;
}

int  __attribute__((section(".crypter"))) PRGA(unsigned char *S, char *data, int len) {

    int i = 0;
    int j = 0;

    for(size_t n = 0; n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];

        data[n] ^= rnd;
    }
    return 0;
}

int  __attribute__((section(".crypter"))) rc4_crypt_blob(uint8_t *data, int data_size, char *key, int key_size) {

    unsigned char S[N];
    KSA(key, key_size, S);
    PRGA(S, data, data_size);

    return 0;
}


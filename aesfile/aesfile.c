#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define MAX_URI 257
#define MAX_BUF 16384
#define DEFAULT_OUT "output.txt"
#define DEFAULT_KEY "abcdefg"

typedef unsigned char uchar;

void printUsage() {
    printf("Usage: ./aes enc/dec filename [-o outputfile] [-p password]\n");
}

int aes_enc(const uchar *in, uchar *out, const char *key, int inLen) {
    static AES_KEY encryptKey;
    int i;

    AES_set_encrypt_key(key, 256, &encryptKey);
    for (i = 0; i < inLen; i += AES_BLOCK_SIZE) {
        AES_encrypt(in + i, out + i, &encryptKey);
    }
    return i;
}

int aes_dec(const uchar *in, uchar *out, const char *key, int inLen) {
    static AES_KEY decryptKey;
    int i;

    AES_set_decrypt_key(key, 256, &decryptKey);
    for (i = 0; i < inLen; i += AES_BLOCK_SIZE) {
        AES_decrypt(in + i, out + i, &decryptKey);
    }
    return i;
}

int main(int argc, char const *argv[]) {
    if (argc % 2 == 0 || argc < 3) {
        printUsage();
        exit(1);
    }

    char inPath[MAX_URI], outPath[MAX_URI], key[MAX_URI];
    FILE *in, *out;

    strcpy(inPath, argv[2]);
    strcpy(outPath, DEFAULT_OUT);
    strcpy(key, DEFAULT_KEY);

    int i;
    for (i = 3; i < argc; ++i) {
        if (argv[i][0] != '-' || strlen(argv[i]) != 2) {
            printUsage();
            exit(2);
        }
        switch (argv[i][1]) {
        case 'o' :
            strcpy(outPath, argv[i + 1]);
            ++i;
            break;
        case 'p' :
            strcpy(key, argv[i + 1]);
            ++i;
            break;
        default  :
            printUsage();
            exit(4);
        }
    }

    in = fopen(inPath, "rb");
    if (in == NULL) {
        perror("cannot open file");
    }

    out = fopen(outPath, "w");
    if (out == NULL) {
        perror("cannot output file");
    }

    if (strcmp(argv[1], "enc") == 0) {
        uchar *inBuf = malloc(MAX_BUF), *outBuf = malloc(MAX_BUF);
        memset(outBuf, 0, MAX_BUF);
        int inLen = fread(inBuf, 1, MAX_BUF, in);
        int outLen;
        outLen = aes_enc(inBuf, outBuf, key, inLen);
        fprintf(out, "%d %d", outLen, inLen);
        fwrite(outBuf, 1, outLen, out);
        printf("output to file: %s\n", outPath);
    } else if (strcmp(argv[1], "dec") == 0) {
        uchar *inBuf = malloc(MAX_BUF), *outBuf = malloc(MAX_BUF);
        memset(outBuf, 0, MAX_BUF);
        int inLen, realLen;
        fscanf(in, "%d %d", &inLen, &realLen);
        fread(inBuf, 1, inLen, in);
        aes_dec(inBuf, outBuf, key, inLen);
        outBuf[realLen] = '\0';
        fwrite(outBuf, 1, realLen, out);
        printf("output to file: %s\n", outPath);
    } else {
        printUsage();
        exit(5);
    }

    fclose(in);
    fclose(out);
    return 0;
}

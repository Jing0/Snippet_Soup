#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include "stack.h"

#define MAX_URI 257
#define MAX_BUF 8192
#define strEqual(str1, str2) (strcmp((str1), (str2)) == 0)
#define lastChar(str) str[strlen(str)-1]

typedef struct directory {
    char path[MAX_URI];
    char name[MAX_URI];
} directory;

void hashIt(char *string, char *mdString, int inLen) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    unsigned char digest[16];

    MD5_Update(&ctx, string, inLen);
    MD5_Final(digest, &ctx);
    
    int i;
    for (i = 0; i < 16; ++i) {
        sprintf(mdString + i * 2, "%02x", (unsigned int)digest[i]);
    }
}

int non_recursive_traverse(const char *dir, int *count) {
    DIR *dirPtr;
    struct dirent *entry;
    struct stat statbuf;
    char fullPath[MAX_URI];
    directory curDir;  /* current Directory */
    sta_t dirStack;

    strcpy(curDir.path, dir);
    strcpy(curDir.name, "");

    stack_new(&dirStack, sizeof(directory));  /* initial a Stack */
    stack_push(&dirStack, &curDir);
    while (dirStack.size > 0) {
        stack_pop(&dirStack, &curDir);
        sprintf(fullPath, "%s%s%s", curDir.path, lastChar(curDir.path) == '/' ? "" : "/", curDir.name);

        if ((dirPtr = opendir(fullPath)) == NULL) {
            perror(fullPath);
        }
        chdir(fullPath);
        while ((entry = readdir(dirPtr)) != NULL) {
            lstat(entry->d_name, &statbuf);
            if (S_ISDIR(statbuf.st_mode)) {
                if (strEqual(".", entry->d_name) || strEqual("..", entry->d_name)) {
                    continue;
                }
                directory newDir;
                strcpy(newDir.path, fullPath);
                strcpy(newDir.name, entry->d_name);
                stack_push(&dirStack, &newDir);
            } else {
                char inBuf[MAX_BUF];
                memset(inBuf, 0, MAX_BUF);
                char mdString[33];

                FILE *fp = fopen(entry->d_name, "r");
                if (fp == NULL) {
                    perror("cannot read file");
                    return 1;
                }
                /* cannot use strlen() when it is a binary file */
                int inLen = fread(inBuf, 1, MAX_BUF, fp);
                fclose(fp);
                hashIt(inBuf, mdString, inLen);
                printf("%-20s\t", entry->d_name);
                printf("MD5:   %s\n", mdString);
                ++(*count);
            }
        }
        chdir("..");
    }
    closedir(dirPtr);
    stack_destroy(&dirStack);
    return 0;
}

int recursive_traverse(const char *dir, int depth, int *count) {
    DIR *dirPtr;
    struct dirent *entry;
    struct stat statbuf;
    if ((dirPtr = opendir(dir)) == NULL) {
        puts("can't open dir.");
    }
    chdir(dir);
    while ((entry = readdir(dirPtr)) != NULL) {
        lstat(entry->d_name, &statbuf);
        if (S_ISDIR(statbuf.st_mode)) {
            if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0) {
                continue;
            }
            printf("%*s%s/\n", depth, "", entry->d_name);
            recursive_traverse(entry->d_name, depth + 4, count);
        } else {
            char inBuf[MAX_BUF];
            memset(inBuf, 0, MAX_BUF);
            char mdString[33];

            FILE *fp = fopen(entry->d_name, "r");
            if (fp == NULL) {
                perror("cannot read file");
                return 1;
            }
            int inLen = fread(inBuf, 1, MAX_BUF, fp);
            fclose(fp);
            hashIt(inBuf, mdString, inLen);
            printf("%*s%-20s\t", depth, "", entry->d_name);
            printf("MD5:   %s\n", mdString);
            ++(*count);
        }
    }
    chdir("..");
    closedir(dirPtr);
    return 0;
}

int main(int argc, char const *argv[]) {
    struct stat statbuf;
    int traverseKind = 0, count = 0, i;
    char path[MAX_URI];

    if (argc == 1) {
        printf("one directory requried\n");
        exit(1);
    }
    for (i = 1; i < argc; ++i) {
        if (strEqual(argv[i], "-t")) {
            traverseKind = atoi(argv[i + 1]);
            ++i;
        } else {
            strcpy(path, argv[i]);
        }
    }
    if (lstat(path, &statbuf) < 0) {
        perror("lstat error");
        exit(2);
    }
    if (!S_ISDIR(statbuf.st_mode)) {
        printf("%s is not a directory\n", argv[1]);
        exit(3);
    }

    if (traverseKind) {
        recursive_traverse(path, 0, &count);
    } else {
        non_recursive_traverse(path, &count);
    }

    printf("total: %d files\n", count);

    return 0;
}

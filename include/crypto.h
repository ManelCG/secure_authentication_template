#ifndef CRYPTO_H
#define CRYPTO_H

#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>


RSA *RSA_gen_key_pair(int bsize);    //Returns pointer to new RSA object
int RSA_to_file(RSA *, char *pub, char *sec, char *pw);   //Returns error code
  //0: Success
  //1: Cant open files for writing

int RSA_from_file(RSA *, char *pub, char *sec, char *pw); //Returns error code
  //0: Success
  //1: File doesnt exist
  //2: No permissions
  //3: Bad formating?

int RSA_from_file_pub(RSA *, char *f);

char *str2hash(char *);  //Returns string with hash of string

RSA *RSA_from_name(char *name, char *pw);   //Returns keys stored in keys/ for user

#endif

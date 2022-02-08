#include <crypto.h>

RSA *RSA_from_name(char *name, char *pw){
  char *pubf = malloc(strlen(name) + 10);
  char *secf = malloc(strlen(name) + 10);

    strcpy(pubf, "keys/");
    strcat(pubf, name);
    strcat(pubf, ".pub");
    strcpy(secf, "keys/");
    strcat(secf, name);
    strcat(secf, ".sec");

    RSA *kp = RSA_new();
    int retval = RSA_from_file(kp, pubf, secf, pw);
    if (retval == 1){
      printf("Generating new keypair...\n");
      kp = RSA_gen_key_pair(4096);
      RSA_to_file(kp, pubf, secf, pw);
    } else if (retval == 2 || retval == 3) {
      perror("Error reading key...");
      kp = NULL;
    }

    free(pubf);
    free(secf);

    return kp;
}

RSA *RSA_gen_key_pair(int bsize){
  RSA *key_pair = NULL;
  BIGNUM *pke = NULL;   //public key exponent e

  pke = BN_new();
  key_pair = RSA_new();

  BN_set_word(pke, RSA_F4);   //RSA_F4 = 65537
  RSA_generate_key_ex(key_pair, bsize, pke, NULL);

  BN_free(pke);
  return key_pair;
}

int RSA_to_file(RSA *rsa, char *pub, char *sec, char *pw){
  FILE *fpp = fopen(pub, "w");
  FILE *fps = fopen(sec, "w");

  //Write public key
  if (!PEM_write_RSAPublicKey(fpp, rsa)){
    perror("Error writing RSA Public key file");
    return 1;
  }

  //Get password length
  int passlen = 0;
  if (pw != NULL){
    passlen = strlen(pw);
  }

  //Write Private key to file
  if (!PEM_write_RSAPrivateKey(fps,
                               rsa,
                               EVP_aes_256_cbc(),
                               (unsigned char *) pw,
                               passlen, NULL, NULL)){
    perror("Error writing RSA Secret key file");
    return 1;
  }

  chmod(pub, 00644);
  chmod(sec, 00600);

  fflush(fpp);
  fflush(fps);
  fclose(fpp);
  fclose(fps);

  return 0;
}

int RSA_from_file_pub(RSA *rsa, char *pub){
  FILE *fpp = NULL;

  if (access(pub, F_OK) == -1) {
    perror("Keypair not found");
    return 1;
  }
  if (access(pub, R_OK) != 0){
    perror("No permissions for reading");
    return 2;
  }

  fpp = fopen(pub, "r");
  RSA *pk = RSA_new();

  if (!PEM_read_RSAPublicKey(fpp, &pk, NULL, NULL)){
    perror("Error reading public key from file. Bad formating?");
    return 3;
  }
  RSA_set0_key(rsa,
               (BIGNUM *)RSA_get0_n(pk),
               (BIGNUM *)RSA_get0_e(pk),
               NULL);

  fflush(fpp);
  fclose(fpp);
  free(pk);

  return 0;
}

int RSA_from_file(RSA *rsa, char *pub, char *sec, char *pw){
  FILE *fpp = NULL;
  FILE *fps = NULL;

  if (access(pub, F_OK) == -1) {
    perror("Keypair not found");
    return 1;
  }
  if (access(pub, R_OK) != 0){
    perror("No permissions for reading");
    return 2;
  }

  if (access(sec, F_OK) == -1){
    perror("Keypair not found");
    return 1;
  }
  if (access(pub, R_OK) != 0){
    perror("No permissions for reading");
    return 2;
  }


  fpp = fopen(pub, "r");
  fps = fopen(sec, "r");

  RSA *pk = RSA_new();
  RSA *sk = RSA_new();

  if (!PEM_read_RSAPublicKey(fpp, &pk, NULL, NULL)){
    perror("Error reading public key from file. Bad formating?");
    return 3;
  }

  if (!PEM_read_RSAPrivateKey(fps, &sk, 0, pw)){
    perror("Error reading secret key from file. Bad formating or password.");
    return 3;
  }

  RSA_set0_key(rsa,
               (BIGNUM *)RSA_get0_n(pk),
               (BIGNUM *)RSA_get0_e(pk),
               (BIGNUM *)RSA_get0_d(sk));

  fflush(fpp);
  fflush(fps);
  fclose(fpp);
  fclose(fps);
  free(pk);
  free(sk);

  return 0;
}

char *str2hash(char *s){
  char *hash = malloc(SHA256_DIGEST_LENGTH);
  SHA256((unsigned const char *) s, strlen(s), (unsigned char *) hash);

  return hash;
}

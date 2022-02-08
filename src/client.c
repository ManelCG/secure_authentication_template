#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <crypto.h>
#include <connection.h>

int main(int argc, char *argv[]){
  char *address = "127.0.0.1";
  int port = 42069;
  char *user = "hrad";

  // RSA *kp = RSA_gen_key_pair(4096);
  // RSA_to_file(kp, "keys/pub", "keys/sec", "Patata");

  RSA *kp = RSA_from_name(user, "Patata");

  int socket_fd = client_init(address, port);
  if (log_into_server(socket_fd, user, kp) == 0){
    printf("Logged into server\n");
  }

  // unsigned char *OTP = malloc(4096);
  // unsigned char *digest = malloc(SHA256_DIGEST_LENGTH);
  // int sig_size = 0;
  // RAND_bytes(OTP, 4096);


  // for (int i = 0; i < 4096; i++){
  //   printf("%d ", OTP[i]);
  // }
  // printf("\n");

  // free(OTP);
  // free(digest);


  free(kp);

}

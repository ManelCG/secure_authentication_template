#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <crypto.h>
#include <connection.h>

int main(int argc, char *argv[]){
  char *address = "127.0.0.1";
  int port = 42069;
  char *user = "hrad";

  RSA *kp = RSA_from_name(user, "Password");

  int socket_fd = client_init(address, port);
  if (log_into_server(socket_fd, user, kp) == 1){
    printf("Logged into server\n");
  } else {
    printf("Unable to log into server\n");
  }

  free(kp);

}

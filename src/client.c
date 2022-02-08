#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <crypto.h>
#include <connection.h>

int main(int argc, char *argv[]){
  char c, *address = NULL, *port_str = NULL, *user = NULL;
  int port;

  while ((c = getopt(argc, argv, "a:P:u:")) != -1){
    switch(c){
      case 'a':
        address = optarg;
        break;
      case 'P':
        port_str = optarg;
        break;
      case 'u':
        user = optarg;
        break;
    }
  }

  if (address == NULL){
    address = "127.0.0.1";
  }
  if (port_str == NULL){
    port = 42069;
  } else {
    port = atoi(port_str);
  }
  if (user == NULL){
    printf("User name must be specified\n");
    exit(1);
  }

  RSA *kp = RSA_from_name(user, "Password");

  if (kp == NULL){
    printf("Error getting keys from file\n");
    exit(1);
  }

  int socket_fd = client_init(address, port);
  if (log_into_server(socket_fd, user, kp) == 1){
    printf("Logged into server\n");
  } else {
    printf("Unable to log into server\n");
  }

  free(kp);

}

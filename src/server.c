#include <crypto.h>
#include <connection.h>

int main(int argc, char *argv[]){
  int port = 42069;

  struct sockaddr_in address;
  socklen_t addrlen = sizeof(address);

  int server_fd = server_init(&address, port);
  int new_connection_fd; //, new_connection_pid;

  while (1){
    //Accepts new connection and creates sockets
    new_connection_fd = accept(server_fd,
                               (struct sockaddr *) &address,
                               &addrlen);

    if (new_connection_fd < 0){
      perror("accept failed");
      exit(EXIT_FAILURE);
    } else {
      if (log_new_user(new_connection_fd) == 1){
        printf("Logged new user\n");
      } else {
        printf("Error logging in new user\n");
      }
    }
  }

  printf("No errors\n");
}


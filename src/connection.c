#include <connection.h>

void log_new_user(char *pubf){
  printf("Logging in new user\n");
}

int client_init(char *addr, int port){
  int sock_fd;
  struct sockaddr_in serv_addr;

  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
    perror("Socket creation error");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  if (inet_pton(AF_INET, addr, &serv_addr.sin_addr) <= 0){
    perror("Invalid address");
    return -1;
  }

  if (connect(sock_fd,
              (struct sockaddr *) &serv_addr,
              sizeof(serv_addr)) < 0){
    perror("Connection failed");
    return -1;
  }

  return sock_fd;
}

int server_init(struct sockaddr_in *addr, int port){
  int server_fd;
  int opt = 1;

  //Build socket
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0){
    perror("Socket failed");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd,
                 SOL_SOCKET,
                 SO_REUSEADDR | SO_REUSEPORT,
                 &opt,
                 sizeof(opt))){
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = INADDR_ANY;
  addr->sin_port = htons(port);

  if (bind(server_fd,
           (struct sockaddr *) addr,
           sizeof(*addr)) < 0){
    perror("Bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, MAX_CONNECTIONS) < 0){
    perror("listen failed");
    exit(EXIT_FAILURE);
  }

  return server_fd;
}

#include <connection.h>

int log_new_user(int fd){
  //Get username
  int userl;
  char *user;
  read(fd, &userl, sizeof(int));
  user = calloc(userl + 1, 1);
  read(fd, user, userl);

  printf("Logging in new user: %s\n", user);

  //Get public key for user
  char *file = malloc(userl + 10);
  strcpy(file, "keys/");
  strcat(file, user);
  strcat(file, ".pub");

  RSA *pub = RSA_new();;
  RSA_from_file_pub(pub, file);

  //Send OTP
  int OTP_len = 420;
  unsigned char *OTP = malloc(OTP_len);
  RAND_bytes(OTP, OTP_len);
  send(fd, &OTP_len, sizeof(int), 0);
  send(fd, OTP, OTP_len, 0);

  //Receive signature
  unsigned char *sig;
  unsigned int sig_size;

  read(fd, &sig_size, sizeof(int));
  sig = malloc(sig_size);
  read(fd, sig, sig_size);

  //Check signature
  if (RSA_verify(NID_sha256, OTP, OTP_len, sig, sig_size, pub) == 1){
    printf("User verified\n");
    return 0;
  } else {
    printf("User unverified\n");
    return 1;
  }
}

int log_into_server(int fd, char *user, RSA *rsa){
  int userlen = strlen(user);

  int OTP_len;
  unsigned char *OTP;

  unsigned char *sig = malloc(sizeof(char) * 4096);
  unsigned int sig_size;

  //Send username
  send(fd, &userlen, sizeof(int), 0);
  send(fd, user, sizeof(char) * userlen, 0);

  //Get OTP

  read(fd, &OTP_len, sizeof(int));
  OTP = malloc(OTP_len);
  read(fd, OTP, OTP_len);

  //Sign OTP
  RSA_sign(NID_sha256, OTP, OTP_len, sig, &sig_size, rsa);

  send(fd, &sig_size, sizeof(int), 0);
  send(fd, sig, sig_size, 0);

  return 0;
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

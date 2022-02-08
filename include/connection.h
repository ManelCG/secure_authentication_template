#ifndef CONNECTION_H
#define CONNECTION_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <crypto.h>

#define MAX_CONNECTIONS 128

int server_init(struct sockaddr_in *, int port);
int client_init(char *addr, int port);

int log_new_user(int socket_fd);
int log_into_server(int fd, char *user, RSA *rsa);


#endif

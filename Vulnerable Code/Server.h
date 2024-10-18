/*
CONTRIBUTORS:
Group 37
Alex Rowe
Darcy Lisk
Michael Marzinotto
Ben Middleton
*/

#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function
#include <fcntl.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <netdb.h>
#include <pthread.h>
#include "Encryption.h"

#define MAX_CLIENTS 100
#define MAX_SERVERS 100
#define SERVER_PORT 8080  // Port to listen on
#define BUFFER_SIZE 2048

typedef struct {
    int socket;
    char public_key[1024];  // PEM formatted RSA public key
    unsigned long last_counter;
} Client;

typedef struct {
    int socket;
    char address[1024];  // PEM formatted RSA public key
    int port;
	char clients[MAX_CLIENTS][1024];
    int server_client_count;
} Server;

extern Client clients[MAX_CLIENTS];
extern int client_count;
extern Server servers[MAX_SERVERS];
extern int server_count;

char *get_host_addr(void);

#endif
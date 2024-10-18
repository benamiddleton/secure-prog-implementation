/*
CONTRIBUTORS:
Group 37
Alex Rowe
Darcy Lisk
Michael Marzinotto
Ben Middleton
*/

#ifndef SERVER2SERVER_H
#define SERVER2SERVER_H

int connect_to_neighbour(int);
void process_server_hello_received(int, const char*);
void process_client_update_request(int socket);
char *get_host_addr(void);

#endif
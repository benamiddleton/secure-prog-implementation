#ifndef SERVER2CLIENT_H
#define SERVER2CLIENT_H

void manage_clients(int server_sock);  // Function to manage incoming client connections
void *handle_client(void *client_socket);  // Threaded function to handle individual clients
void route_message(const char *message, const char *sender_id);  // Function to route client messages

#endif

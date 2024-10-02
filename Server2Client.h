#ifndef SERVER2CLIENT_H
#define SERVER2CLIENT_H

void route_message(const char *message, const char *sender_id);  // Function to route client messages
void add_client(int client_sock, const char* public_key);  // Add new client to the list
void send_message_to_client(int client_sock, const char* message);  // Send message to a specific client
void broadcast_public_message(int sender_sock, const char* message);  // Broadcast message to all clients
void handle_chat_message(int sender_sock, const char* message);  // Handle chat message routing
void process_client_message(int client_sock, const char* message);  // Process incoming client messages
char* extract_field(const char* message, const char* field);
void process_client_list_request(int socket);

#endif

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include "Server2Client.h"
#include "Server2Server.h"
#include "Encryption.h"  // for RSA/AES encryption

#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024

// Struct to hold client details
typedef struct {
    int socket;
    char public_key[1024];  // PEM formatted RSA public key
    unsigned long last_counter;
} Client;

Client clients[MAX_CLIENTS];
int client_count = 0;

// Add new client to the client list
void add_client(int client_sock, const char* public_key) {
    if (client_count < MAX_CLIENTS) {
        clients[client_count].socket = client_sock;
        strncpy(clients[client_count].public_key, public_key, sizeof(clients[client_count].public_key));
        clients[client_count].last_counter = 0;  // Start counter from 0
        client_count++;
    } else {
        printf("Max client limit reached\n");
    }
}

// Find a client by socket
Client* find_client(int client_sock) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket == client_sock) {
            return &clients[i];
        }
    }
    return NULL;
}

// Verify message signature
int verify_message(const char* message, const char* signature, const char* public_key) {
    //Use RSA verify to check if signature matches message
    verify_signature(EVP_PKEY* public_key, const char* message, size_t message_len, const char* signature);
}

// Process incoming message from client
void process_client_message(int client_sock, const char* message) {
    // Extract message fields
    // Parse JSON message 
    char* type = extract_field(message, "type");
    unsigned long counter = extract_counter(message);
    char* signature = extract_field(message, "signature");
    
    // Find client and verify counter & signature
    Client* client = find_client(client_sock);
    if (client == NULL || counter <= client->last_counter || !verify_message(message, signature, client->public_key)) {
        printf("Invalid message received\n");
        return;
    }

    // Update counter
    client->last_counter = counter;

    // Route message based on type
    if (strcmp(type, "chat") == 0) {
        // Handle chat message routing
        handle_chat_message(client_sock, message);
    } else if (strcmp(type, "public_chat") == 0) {
        // Broadcast public message
        broadcast_public_message(client_sock, message);
    } else {
        printf("Unknown message type: %s\n", type);
    }
}

// Send message to a specific client
void send_message_to_client(int client_sock, const char* message) {
    send(client_sock, message, strlen(message), 0);
}

// Broadcast public message to all clients
void broadcast_public_message(int sender_sock, const char* message) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != sender_sock) {
            send_message_to_client(clients[i].socket, message);
        }
    }
}

// Handle chat message routing
void handle_chat_message(int sender_sock, const char* message) {
    // Extract destination servers and route message to the appropriate server/client
    char* destination_server = extract_field(message, "destination_server");

    if (strcmp(destination_server, get_local_server_address()) == 0) {
        // The destination client is on this server, route directly to the client
        char* recipient_fingerprint = extract_recipient_fingerprint(message);
        int recipient_sock = find_client_by_fingerprint(recipient_fingerprint);
        send_message_to_client(recipient_sock, message);
    } else {
        // Forward to the appropriate server
        forward_message_to_server(destination_server, message);
    }
}


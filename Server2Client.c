#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <pthread.h>
#include "Server2Client.h"
#include "Server2Server.h"
#include "Encryption.h"
#include <libwebsockets.h>
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
        printf("Client added\nSocket: %d\nPublic Key: %s\nCounter: %d\n",client_sock,public_key,clients[client_count-1].last_counter);
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

// Extract a field from a JSON message
char* extract_field(const char* message, const char* field) {
    struct json_object *parsed_json;
    struct json_object *field_value;

    parsed_json = json_tokener_parse(message);
    if (json_object_object_get_ex(parsed_json, field, &field_value)) {
        return strdup(json_object_get_string(field_value));
    }
    return NULL;
}

// Extract counter from a JSON message
unsigned long extract_counter(const char* message) {
    char *counter_str = extract_field(message, "counter");
    if (counter_str != NULL) {
        unsigned long counter = strtoul(counter_str, NULL, 10);
        free(counter_str);
        return counter;
    }
    return 0;
}

// Get the local server address (hardcoded for now, could be dynamic)
char* get_local_server_address() {
    return "127.0.0.1";  // Example local server IP
}

// Extract recipient fingerprint from the message (if needed)
char* extract_recipient_fingerprint(const char* message) {
    return extract_field(message, "recipient_fingerprint");
}

// Find client by fingerprint (for routing to specific clients)
int find_client_by_fingerprint(const char* fingerprint) {
    for (int i = 0; i < client_count; i++) {
        // Assuming public_key as fingerprint (for simplicity)
        if (strcmp(clients[i].public_key, fingerprint) == 0) {
            return clients[i].socket;
        }
    }
    return -1;  // Client not found
}

// Forward message to another server
void forward_message_to_server(const char* destination_server, const char* message) {
    // Placeholder: You need to establish a connection to the destination server and forward the message
    printf("Forwarding message to server: %s\n", destination_server);
    // Open socket, send message, and close socket
}

// Process incoming message from client
void process_client_message(int client_sock, const char* message) {
    // Extract fields from the JSON message
    char* type = extract_field(extract_field(message, "data"), "type");
    unsigned long counter = extract_counter(message);
    char* signature = extract_field(message, "signature");

    // Find the client and verify message
    // Client* client = find_client(client_sock);
    // if (client == NULL || counter <= client->last_counter /*|| !verify_message(message, signature, client->public_key)*/) {
    //     printf("Invalid message received\n");
    //     return;
    // }

    // Update client's counter
    // client->last_counter = counter;

    // Route message based on type
    if (strcmp(type, "hello") == 0) {
        add_client(client_sock, extract_field(extract_field(message, "data"), "public_key"));
    } else if (strcmp(type, "chat") == 0) {
        handle_chat_message(client_sock, message);
    } else if (strcmp(type, "public_chat") == 0) {
        broadcast_public_message(client_sock, message);
    } else {
        printf("Unknown message type: %s\n", type);
    }

    free(type);
    free(signature);
}

// Handle chat message routing
void handle_chat_message(int sender_sock, const char* message) {
    char* destination_server = extract_field(message, "destination_server");

    if (strcmp(destination_server, get_local_server_address()) == 0) {
        // Route message to the appropriate client on this server
        char* recipient_fingerprint = extract_recipient_fingerprint(message);
        int recipient_sock = find_client_by_fingerprint(recipient_fingerprint);
        send_message_to_client(recipient_sock, message);
        free(recipient_fingerprint);
    } else {
        // Forward the message to the destination server
        forward_message_to_server(destination_server, message);
    }

    free(destination_server);
}

// Verify message signature (stub for actual RSA/AES verification)
int verify_message(const char* message, const char* signature, const char* public_key) {
    size_t message_len = strlen(message);
    return verify_signature(public_key, message, message_len, signature);
}

#include "Server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 512
#define MAX_CLIENTS 100
#define MAX_MESSAGE_SIZE 5000
#define ERROR_RESPONSE_SIZE 5000 // Size for the error message buffer

// Function to extract the client's message from the JSON input
char* extract_client_message(const char* json_message) {
    // Locate the "message" field in the JSON
    const char* message_start = strstr(json_message, "\"message\": \"");
    if (message_start) {
        message_start += strlen("\"message\": \""); // Move past the key

        // Find the end of the message
        const char* message_end = strstr(message_start, "\"");
        if (message_end) {
            size_t message_length = message_end - message_start;

            // Allocate memory for the client message
            char* client_message = (char*)malloc(message_length + 1);
            if (client_message) {
                strncpy(client_message, message_start, message_length);
                client_message[message_length] = '\0'; // Null-terminate the string

                // Trim any trailing newline or carriage return characters
                char* ptr = client_message + message_length - 1;
                while (ptr >= client_message && (*ptr == '\n' || *ptr == '\r' || *ptr == ' ')) {
                    *ptr-- = '\0'; // Replace with null terminator
                }
                
                return client_message;
            }
        }
    }
    return NULL; // Return NULL if the message is not found
}

/*// Add new client to the client list
void add_client(int client_sock, const char* public_key) {
    if (client_count < MAX_CLIENTS) {
        clients[client_count].socket = client_sock;
        strncpy(clients[client_count].public_key, public_key, sizeof(clients[client_count].public_key));
        clients[client_count].last_counter = 0;  // Start counter from 0
        client_count++;
        send(client_sock, "Hello received!", 15, 0);
    } else {
        printf("Max client limit reached\n");
    }
}*/

// Initialize client_count by reading from the server_list.txt file
void initialize_client_count() {
    FILE *file = fopen("server_list.txt", "r");
    if (!file) {
        printf("Could not open server_list.txt. Starting with 0 clients.\n");
        client_count = 0;
        return;
    }
    
    client_count = 0;
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        // Skip empty or malformed lines (you could add further validation here)
        if (strlen(line) > 1) {
            client_count++;
        }
    }
    
    fclose(file);
    printf("Initialized with %d clients from file.\n", client_count);
}

void add_client(int client_sock, const char* public_key) {
    if (client_count < MAX_CLIENTS) {
        
        // Hash the public key
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)public_key, strlen(public_key), hash);
        
        // Convert the hash to a readable hex format (or Base64)
        char hash_string[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(&hash_string[i * 2], "%02x", hash[i]);
        }

        //clients[client_count].last_counter = 0;  // Start counter from 0
        client_count++;
        send(client_sock, "Hello received!", 15, 0);
        
        // Optionally, store the hash and other details in server_list.txt
        FILE *file = fopen("server_list.txt", "a");
        if (file) {
            fprintf(file, "client%d | %s | %d\n", client_count, hash_string, client_sock);
            fclose(file);
        }
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
    char* client_message = extract_client_message(message);
    for (int i = 0; i < client_count; i++) {
        //if (clients[i].socket != sender_sock) {
        printf("Client message: %s", client_message);
        send_message_to_client(sender_sock, message); // change to clients[i].socket
        //}
    }
}

/*void broadcast_public_message(int sender_sock, const char* json_message) {
    char* client_message = extract_client_message(json_message);
    if (client_message) {
        for (int i = 0; i < client_count; i++) {
            if (clients[i].socket != sender_sock && clients[i].socket > 0) {
                printf("Broadcasting to client %d: %s\n", clients[i].socket, client_message);

                // Send only the client message to the client
                if (send_message_to_client(clients[i].socket, client_message) < 0) {
                    perror("Failed to send message");
                    close(clients[i].socket);  // Close the socket if there's an error
                    clients[i].socket = -1;    // Mark this socket as invalid
                }
            }
        }
    } else {
        printf("Error: Could not extract client message from JSON.\n");
    }

    // Free the allocated memory for the client message
    free(client_message); // Ensure to free the message
}*/

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

void process_client_list_request(int socket) {
    json_object *message_json, *server_array, *this_server;
    char *message, *alloc_message;

    message_json = json_object_new_object();
    json_object_object_add(message_json, "type", json_object_new_string("client_list"));
    server_array = json_object_new_array();
    this_server = json_object_new_object();
    json_object_object_add(this_server, "address", json_object_new_string(get_host_addr()));
    json_object *this_server_client_array = json_object_new_array();
    for (int i=0;i<client_count;i++) {
        json_object_array_add(this_server_client_array, json_object_new_string(clients[i].public_key));
    }
    json_object_object_add(this_server, "clients", this_server_client_array);
    json_object_array_add(server_array, this_server);
    for (int i=0;i<server_count;i++) {
        json_object *server = json_object_new_object();
        json_object_object_add(server, "address", json_object_new_string(servers[i].address));
        json_object *client_array = json_object_new_array();
        for (int j=0;j<servers[i].server_client_count;j++) {
            json_object_array_add(client_array, json_object_new_string(servers[i].clients[j]));
        }
        json_object_object_add(server, "clients", client_array);
        json_object_array_add(server_array, server);
    }
    json_object_object_add(message_json, "servers", server_array);
    message = json_object_to_json_string(message_json);
    alloc_message = strdup(message);
    // printf("%s\n", alloc_message);
    send(socket, alloc_message, strlen(alloc_message), 0);
}

// Process incoming message from client
void process_client_message(int client_sock, const char* message) {
    //printf("TEST");
    //fflush(stdout);

    // Extract fields from the JSON message
    char* type = extract_field(extract_field(message, "data"), "type");
    unsigned long counter = extract_counter(message);
    char* signature = extract_field(message, "signature");

    //printf("%s", message);
    //fflush(stdout);
    //printf("PROCESS_CLIENT_MESSAGE");
    //fflush(stdout);

    // Find the client and verify message
    // Client* client = find_client(client_sock);
    // if (client == NULL || counter <= client->last_counter /*|| !verify_message(message, signature, client->public_key)*/) {
    //     printf("Invalid message received\n");
    //     return;
    // }

    // Update client's counter
    // client->last_counter = counter;



    // Route message based on type ###################   TAKE THIS OUT FOR BUFFER OVERFLOW     ###########
    if (strlen(message) > MAX_MESSAGE_SIZE) {
        printf("Message received is too long: %lu bytes (max: %d)\n", strlen(message), MAX_MESSAGE_SIZE);

        // Create the error response message
        char error_response[ERROR_RESPONSE_SIZE];
        snprintf(error_response, ERROR_RESPONSE_SIZE, "{\"type\":\"error\",\"message\":\"Message too long\"}");

        // Send the error response back to the client
        send(client_sock, error_response, strlen(error_response), 0);
        
        return; // Early return to prevent further processing
    }
     ///////////////////////////////////////////////////////////////////////////////////////

    // Route message based on type
    if (strcmp(type, "hello") == 0) {
        //printf("POGGG");
        //fflush(stdout);
        add_client(client_sock, extract_field(extract_field(message, "data"), "public_key"));
    } else if (strcmp(type, "chat") == 0) {
        handle_chat_message(client_sock, message);
    } else if (strcmp(type, "public_chat") == 0) {
        broadcast_public_message(client_sock, message);
        //printf("WOOOO");
        fflush(stdout);
    } else {
        printf("Unknown message type: %s\n", type);
        fflush(stdout);

         // Create the unknown message type response
        char unknown_response[ERROR_RESPONSE_SIZE];
        snprintf(unknown_response, ERROR_RESPONSE_SIZE, "{\"type\":\"error\",\"message\":\"Unknown message type\"}");

        // Send the unknown message type response back to the client
        send(client_sock, unknown_response, strlen(unknown_response), 0);
    }
    
    free(type);
    free(signature);
}

// Handle chat message routing
void handle_chat_message(int sender_sock, const char* message) {
    char *data = extract_field(message, "data");
    json_object *data_obj = json_tokener_parse(data);
    json_object *dest_servers;
    json_object_object_get_ex(data_obj, "destination_servers", &dest_servers);
    json_object *dest = json_object_array_get_idx(dest_servers, 0);
    char *destination_server = json_object_get_string(dest);

    char* client_message = extract_client_message(message);
    
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

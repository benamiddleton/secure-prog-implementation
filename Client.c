#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <json-c/json.h>  // Replacing jansson with json-c
#include <openssl/aes.h>
#include <libwebsockets.h>
#include "Encryption.h"

#define SERVER_PORT 8080  // Port to connect to

// // Base64 encoding function (pseudo-code, replace with a real implementation)
// char* base64_encode(const unsigned char* buffer, size_t length) {
//     // You'll need to use a real base64 encoding function, such as from OpenSSL or another library.
//     // This is just a placeholder.
//     return NULL;
// }

// char* sign_message(const char *message, int counter) {
//     // Combine message and counter into a single string
//     char full_message[512];
//     sprintf(full_message, "%s%d", message, counter);
    
//     // Hash the message using SHA-256
//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256((unsigned char*)full_message, strlen(full_message), hash);

//     // Load the private key
//     RSA *rsa = RSA_new();
//     FILE *fp = fopen("private.pem", "r");
//     PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
//     fclose(fp);
    
//     // Sign the hash
//     unsigned char *signature = malloc(RSA_size(rsa));
//     unsigned int signature_len;
//     RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signature_len, rsa);

//     // Base64 encode the signature (replace this with a real base64 encoding implementation)
//     char *encoded_signature = base64_encode(signature, signature_len);
    
//     RSA_free(rsa);
//     free(signature);
    
//     return encoded_signature;
// }

void send_hello(int websocket) {
    // Create a new JSON object using json-c
    json_object *json_message = json_object_new_object();
    json_object *data = json_object_new_object();
    EVP_PKEY *private_key = generate_rsa_key();
    char *message, *signature;
    

    // Create "hello" message
    json_object_object_add(json_message, "type", json_object_new_string("signed_data"));
    json_object_object_add(data, "type", json_object_new_string("hello"));
    json_object_object_add(data, "public_key", json_object_new_string(get_public_key_pem(private_key)));
    json_object_object_add(json_message, "data", data);
    json_object_object_add(json_message, "counter", json_object_new_int(0));
    message = json_object_get_string(data);
    signature = malloc(sizeof(char)*SIGNATURE_SIZE);
    sign_message(private_key,message,strlen(message), signature);
    json_object_object_add(json_message, "signature", json_object_new_string(signature));

    const char *json_str = json_object_to_json_string(json_message);
    // Assuming lws_write is used for WebSocket communication
    
    send(websocket, json_str, strlen(json_str), 0);

    json_object_put(json_message);  // Free memory
}

void send_chat_message(int websocket, const char *message, const char *recipient_public_key) {
    // Encrypt the message using AES
    unsigned char aes_key[32];  // Generate a random AES key
    unsigned char iv[AES_BLOCK_SIZE];
    AES_KEY encrypt_key;
    AES_set_encrypt_key(aes_key, 256, &encrypt_key);

    unsigned char encrypted_message[256];
    AES_cfb128_encrypt((unsigned char*)message, encrypted_message, strlen(message), &encrypt_key, iv, NULL, AES_ENCRYPT);

    // Encrypt the AES key with recipient's RSA public key
    RSA *rsa = RSA_new();
    FILE *fp = fopen("recipient_public.pem", "r");
    PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    fclose(fp);

    unsigned char encrypted_key[256];
    int encrypted_key_len = RSA_public_encrypt(sizeof(aes_key), aes_key, encrypted_key, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    // Create the JSON message using json-c
    json_object *json_message = json_object_new_object();
    json_object *data = json_object_new_object();
    json_object_object_add(data, "type", json_object_new_string("chat"));
    json_object_object_add(data, "iv", json_object_new_string(base64_encode(iv, AES_BLOCK_SIZE)));
    json_object_object_add(data, "symm_keys", json_object_new_string(base64_encode(encrypted_key, encrypted_key_len)));
    json_object_object_add(data, "chat", json_object_new_string(base64_encode(encrypted_message, sizeof(encrypted_message))));
    json_object_object_add(json_message, "data", data);

    const char *json_str = json_object_to_json_string(json_message);
    send(websocket, json_str, strlen(json_str), 0);

    json_object_put(json_message);  // Free memory
}

// Function to create a JSON public chat message
char* create_public_chat(const char* sender_fingerprint, const char* message) {
    // Create a new JSON object using json-c
    json_object *data_obj = json_object_new_object();

    // Add fields to the JSON object
    json_object_object_add(data_obj, "type", json_object_new_string("public_chat"));
    json_object_object_add(data_obj, "sender", json_object_new_string(sender_fingerprint));
    json_object_object_add(data_obj, "message", json_object_new_string(message));

    // Wrap the data object into a top-level object
    json_object *root = json_object_new_object();
    json_object_object_add(root, "data", data_obj);

    // Convert JSON object to a string
    const char *json_string_output = json_object_to_json_string(root);

    // Free the JSON objects
    json_object_put(root);

    return strdup(json_string_output);  // The caller should free this string after use
}

// Function to create a JSON client list request
char* create_client_list_request() {
    // Create a new JSON object using json-c
    json_object *root = json_object_new_object();

    // Add the "type" field to indicate a client list request
    json_object_object_add(root, "type", json_object_new_string("client_list_request"));

    // Convert JSON object to a string
    const char *json_string_output = json_object_to_json_string(root);

    // Free the JSON object
    json_object_put(root);

    return strdup(json_string_output);  // The caller should free this string after use
}

// Function to create a JSON client list response
char* create_client_list_response(const char** server_addresses, const char*** clients, int server_count) {
    // Create the root JSON object using json-c
    json_object *root = json_object_new_object();
    json_object_object_add(root, "type", json_object_new_string("client_list"));

    // Create a JSON array to hold the servers
    json_object *servers_array = json_object_new_array();

    for (int i = 0; i < server_count; i++) {
        // Create a JSON object for each server
        json_object *server_obj = json_object_new_object();
        json_object_object_add(server_obj, "address", json_object_new_string(server_addresses[i]));

        // Create a JSON array for clients
        json_object *clients_array = json_object_new_array();
        for (int j = 0; clients[i][j] != NULL; j++) {
            json_object_array_add(clients_array, json_object_new_string(clients[i][j]));
        }

        // Add the clients array to the server object
        json_object_object_add(server_obj, "clients", clients_array);

        // Add the server object to the servers array
        json_object_array_add(servers_array, server_obj);
    }

    // Add the servers array to the root object
    json_object_object_add(root, "servers", servers_array);

    // Convert JSON object to a string
    const char *json_string_output = json_object_to_json_string(root);

    // Free the JSON objects
    json_object_put(root);

    return strdup(json_string_output);  // The caller should free this string after use
}

json_object *get_client_list(int socket) {
    json_object *client_request, *response;
    char *buffer;

    client_request = json_object_new_object();
    json_object_object_add(client_request, "type", json_object_new_string("client_list_request"));

    const char *json_str = json_object_to_json_string(client_request);
    
    send(socket, json_str, strlen(json_str), 0);
    json_object_put(client_request);
    buffer = malloc(sizeof(char) * 65536);
    recv(socket, buffer, 65536, 0);
    response = json_tokener_parse(buffer);
    free(buffer);
    return response;
}

int main() {
    int sock;  // Socket descriptor
    struct sockaddr_in server_addr;  // Server address
    char choice[16], message[256], *sender_fingerprint;
    EVP_PKEY *recipient_key;

    // Create the socket (IPv4, TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // Set up the server address (IP and port)
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_port = htons(SERVER_PORT);  // Convert port to network byte order
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Server address (localhost)

    // Connect to the server
    connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    // Send the message to the server
    send_hello(sock);
    printf("Connected to Server\n");
    printf("Options:\n");
    printf("type PRIVATE to send a private message.\n");
    printf("type PUBLIC to send a public message to all.\n");
    scanf(choice);
    printf("What is your message? (MAX 256 characters)\n");
    scanf(message);
    if (strcmp(choice, "PRIVATE")) {
        // TO DO: add logic to receive recipient as user input and locate their public key
        send_chat_message(sock, message, recipient_key);
    } else if (strcmp(choice, "PUBLIC")) {
        create_public_chat(sender_fingerprint, message);
    }
    // send(sock, message, strlen(message), 0);

    // Close the socket
    close(sock);

    return 0;
}

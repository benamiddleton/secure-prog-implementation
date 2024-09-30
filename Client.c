#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <openssl/aes.h>
#include <jansson.h>

#define SERVER_PORT 8080  // Port to connect to


int main() {
    int sock;  // Socket descriptor
    struct sockaddr_in server_addr;  // Server address
    char message[256] = "Hello, Server!";  // Message to send

    // Create the socket (IPv4, TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // Set up the server address (IP and port)
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_port = htons(SERVER_PORT);  // Convert port to network byte order
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Server address (localhost)

    // Connect to the server
    connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    // Send the message to the server
    send(sock, message, strlen(message), 0);


    char* sign_message(const char *message, int counter) {
    // Combine message and counter into a single string
    char full_message[512];
    sprintf(full_message, "%s%d", message, counter);
    
    // Hash the message using SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)full_message, strlen(full_message), hash);

    // Load the private key
    RSA *rsa = RSA_new();
    FILE *fp = fopen("private.pem", "r");
    PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    fclose(fp);
    
    // Sign the hash
    unsigned char *signature = malloc(RSA_size(rsa));
    unsigned int signature_len;
    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signature_len, rsa);

    // Base64 encode the signature (pseudo-code, you'll need to use a real library)
    char *encoded_signature = base64_encode(signature, signature_len);
    
    RSA_free(rsa);
    free(signature);
    
    return encoded_signature;
}

void send_hello(int websocket) {
    json_object *json_message = json_object_new_object();
    json_object *data = json_object_new_object();

    // Create "hello" message
    json_object_object_add(data, "type", json_object_new_string("hello"));
    json_object_object_add(data, "public_key", json_object_new_string("<Your Public Key PEM>"));
    json_object_object_add(json_message, "data", data);

    const char *json_str = json_object_to_json_string(json_message);
    lws_write(websocket, (unsigned char*)json_str, strlen(json_str), LWS_WRITE_TEXT);

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

    // Create the JSON message
    json_object *json_message = json_object_new_object();
    json_object *data = json_object_new_object();
    json_object_object_add(data, "type", json_object_new_string("chat"));
    json_object_object_add(data, "iv", json_object_new_string(base64_encode(iv, AES_BLOCK_SIZE)));
    json_object_object_add(data, "symm_keys", json_object_new_string(base64_encode(encrypted_key, encrypted_key_len)));
    json_object_object_add(data, "chat", json_object_new_string(base64_encode(encrypted_message, sizeof(encrypted_message))));
    json_object_object_add(json_message, "data", data);

    const char *json_str = json_object_to_json_string(json_message);
    lws_write(websocket, (unsigned char*)json_str, strlen(json_str), LWS_WRITE_TEXT);

    json_object_put(json_message);  // Free memory
}

// Function to create a JSON public chat message
char* create_public_chat(const char* sender_fingerprint, const char* message) {
    // Create a new JSON object
    json_t *data_obj = json_object();

    // Add fields to the JSON object
    json_object_set_new(data_obj, "type", json_string("public_chat"));
    json_object_set_new(data_obj, "sender", json_string(sender_fingerprint));
    json_object_set_new(data_obj, "message", json_string(message));

    // Wrap the data object into a top-level object
    json_t *root = json_object();
    json_object_set_new(root, "data", data_obj);

    // Convert JSON object to a string
    char *json_string_output = json_dumps(root, JSON_COMPACT);

    // Free the JSON objects
    json_decref(root);

    return json_string_output;  // The caller should free this string after use
}

// Function to create a JSON client list request
char* create_client_list_request() {
    // Create a new JSON object
    json_t *root = json_object();

    // Add the "type" field to indicate a client list request
    json_object_set_new(root, "type", json_string("client_list_request"));

    // Convert JSON object to a string
    char *json_string_output = json_dumps(root, JSON_COMPACT);

    // Free the JSON object
    json_decref(root);

    return json_string_output;  // The caller should free this string after use
}

// Function to create a JSON client list response
char* create_client_list_response(const char** server_addresses, const char*** clients, int server_count) {
    // Create the root JSON object
    json_t *root = json_object();
    json_object_set_new(root, "type", json_string("client_list"));

    // Create a JSON array to hold the servers
    json_t *servers_array = json_array();

    for (int i = 0; i < server_count; i++) {
        // Create a JSON object for each server
        json_t *server_obj = json_object();
        json_object_set_new(server_obj, "address", json_string(server_addresses[i]));

        // Create a JSON array for clients
        json_t *clients_array = json_array();
        for (int j = 0; clients[i][j] != NULL; j++) {
            json_array_append_new(clients_array, json_string(clients[i][j]));
        }

        // Add the clients array to the server object
        json_object_set_new(server_obj, "clients", clients_array);

        // Add the server object to the servers array
        json_array_append_new(servers_array, server_obj);
    }

    // Add the servers array to the root object
    json_object_set_new(root, "servers", servers_array);

    // Convert JSON object to a string
    char *json_string_output = json_dumps(root, JSON_COMPACT);

    // Free the JSON objects
    json_decref(root);

    return json_string_output;  // The caller should free this string after use
}

def handle_hello_message(message):
    // Parse the hello message
    try:
        message_data = message['data']
        if message_data['type'] == 'hello':
            sender_fingerprint = message_data['sender']
            print(f"Hello from client: {sender_fingerprint}")
            // Handle any further actions, like adding the sender to a client list
            // update_client_list(sender_fingerprint)
        else:
            print("Received unexpected message type in hello handler")
    except KeyError:
        print("Malformed hello message")

// Example usage:
// handle_hello_message({ "data": { "type": "hello", "sender": "client_fingerprint" } })

def handle_chat_message(message):
    // Parse the chat message
    try:
        message_data = message['data']
        if message_data['type'] == 'chat':
            sender_fingerprint = message_data['sender']
            encrypted_message = message_data['message']
            // Decrypt the message if needed, here we assume it's already decrypted
            print(f"Chat message from {sender_fingerprint}: {encrypted_message}")
        else:
            print("Received unexpected message type in chat handler")
    except KeyError:
        print("Malformed chat message")

// Example usage:
// handle_chat_message({ "data": { "type": "chat", "sender": "client_fingerprint", "message": "Hello there!" } })

def handle_public_chat_message(message):
    // Parse the public chat message
    try:
        message_data = message['data']
        if message_data['type'] == 'public_chat':
            sender_fingerprint = message_data['sender']
            plaintext_message = message_data['message']
            print(f"Public message from {sender_fingerprint}: {plaintext_message}")
        else:
            print("Received unexpected message type in public chat handler")
    except KeyError:
        print("Malformed public chat message")

// Example usage:
// handle_public_chat_message({ "data": { "type": "public_chat", "sender": "client_fingerprint", "message": "This is a public message" } })

def handle_message(message):
    message_type = message.get('data', {}).get('type')
    
    if message_type == 'hello':
        handle_hello_message(message)
    elif message_type == 'chat':
        handle_chat_message(message)
    elif message_type == 'public_chat':
        handle_public_chat_message(message)
    else:
        print(f"Unknown message type: {message_type}")

// Example usage:
// message = { "data": { "type": "public_chat", "sender": "client_fingerprint", "message": "Hello everyone!" } }
// handle_message(message)



    // Close the socket
    close(sock);

    return 0;
}
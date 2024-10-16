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
#include "Encryption.h"

#define SERVER_PORT 8080  // Port to connect to

char public_keys[100][1024];
int public_key_count = 0;
int counter = 0;
EVP_PKEY *private_key;

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

char* send_hello(int websocket) {
    // Create a new JSON object using json-c
    json_object *json_message = json_object_new_object();
    json_object *data = json_object_new_object();
    private_key = generate_rsa_key();
    char *message, *signature, *public_key;
    public_key = get_public_key_pem(private_key);
    

    // Create "hello" message
    json_object_object_add(json_message, "type", json_object_new_string("signed_data"));
    json_object_object_add(data, "type", json_object_new_string("hello"));
    json_object_object_add(data, "public_key", json_object_new_string(public_key));
    json_object_object_add(json_message, "data", data);
    json_object_object_add(json_message, "counter", json_object_new_int(counter++));
    message = json_object_get_string(data);
    signature = malloc(sizeof(char)*SIGNATURE_SIZE);
    sign_message(private_key,message,strlen(message), signature);
    json_object_object_add(json_message, "signature", json_object_new_string(signature));
    
    const char *json_str = json_object_to_json_string(json_message);
    // Assuming lws_write is used for WebSocket communication
    if (send(websocket, strdup(json_str), strlen(json_str), 0) < 0) {
        perror("failed to send hello");
    }

    printf("%s", message);
    fflush(stdout);

    json_object_put(json_message);  // Free memory

    char buffer[1024];
    recv(websocket, buffer, sizeof(buffer), 0);
    printf("%s\n", buffer);

    return(public_key);
}

void send_chat_message(int websocket, const char *message, const char *recipient_public_key) {
    // Encrypt the message using AES
    unsigned char aes_key[32];  // Generate a random AES key
    unsigned char *iv = malloc(sizeof(unsigned char)*AES_BLOCK_SIZE);
    int num = 0;
    AES_KEY encrypt_key;
    AES_set_encrypt_key(aes_key, 256, &encrypt_key);

    unsigned char *encrypted_message = malloc(sizeof(unsigned char) * 256);
    AES_cfb128_encrypt((unsigned char*)message, encrypted_message, strlen(message), &encrypt_key, iv, &num, AES_ENCRYPT);
    

    // Encrypt the AES key with recipient's RSA public key
    RSA *rsa = RSA_new();
    FILE *fp = fopen("recipient_public.pem", "rw");
    PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    fclose(fp);

    unsigned char encrypted_key[256];
    int encrypted_key_len = RSA_public_encrypt(sizeof(aes_key), aes_key, encrypted_key, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);

    // Create the JSON message using json-c
    json_object *json_message = json_object_new_object();
    json_object *data = json_object_new_object();
    json_object_object_add(json_message, "type", json_object_new_string("signed_data"));
    json_object_object_add(data, "type", json_object_new_string("chat"));
    json_object *dest_servers = json_object_new_array();
    json_object_array_add(dest_servers, json_object_new_string("127.0.0.1"));
    json_object_object_add(data, "destination_servers", dest_servers);
    json_object_object_add(data, "iv", json_object_new_string(base64_encode(iv, AES_BLOCK_SIZE)));
    json_object_object_add(data, "symm_keys", json_object_new_string(base64_encode(encrypted_key, encrypted_key_len)));
    json_object_object_add(data, "chat", json_object_new_string(base64_encode(encrypted_message, sizeof(encrypted_message))));
    json_object_object_add(json_message, "data", data);
    json_object_object_add(json_message, "counter", json_object_new_int(counter++));
    char *signature = malloc(sizeof(char)*SIGNATURE_SIZE);
    sign_message(private_key,message,strlen(message), signature);
    json_object_object_add(json_message, "signature", json_object_new_string(signature));

    const char *json_str = json_object_to_json_string(json_message);
    send(websocket, json_str, strlen(json_str), 0);

    json_object_put(json_message);  // Free memory
}

// Function to create a JSON public chat message
char* create_public_chat(int websocket, const char* sender_fingerprint, const char* message) {
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
    printf("HERE");
    printf("%s", json_string_output);
    fflush(stdout);

    send(websocket, json_string_output, strlen(json_string_output), 0);

    // Free the JSON objects
    json_object_put(root);

    return strdup(json_string_output);  // The caller should free this string after use
}

void get_client_list(int socket) {
    json_object *client_request, *response, *servers_json, *clients_json;
    char buffer[65536], *list;

    client_request = json_object_new_object();
    json_object_object_add(client_request, "type", json_object_new_string("client_list_request"));

    const char *json_str = json_object_to_json_string(client_request);
    
    send(socket, json_str, strlen(json_str), 0);
    
    json_object_put(client_request);
    recv(socket, buffer, sizeof(buffer), 0);
    
    list = strdup(buffer);
    response = json_tokener_parse(list);
    json_object_object_get_ex(response, "servers", &servers_json);
    int servers_len = json_object_array_length(servers_json);
    for (int i=0;i<servers_len;i++) {
        json_object *server = json_object_array_get_idx(servers_json, i);
        json_object_object_get_ex(server, "clients", &clients_json);
        int clients_len = json_object_array_length(clients_json);
        for (int j=0;j<clients_len;j++) {
            json_object *client = json_object_array_get_idx(clients_json, j);
            strcpy(public_keys[j], json_object_get_string(client));
            public_key_count++;
        }
    }
    // return list;
}

void receive_message(int socket) {
    char buffer[1024];  // Buffer to store received data
    memset(buffer, 0, sizeof(buffer));  // Clear buffer

    ssize_t bytes_received = recv(socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("recv failed");
    } else if (bytes_received == 0) {
        printf("Connection closed by the server.\n");
    } else {
        buffer[bytes_received] = '\0';  // Null-terminate the received data
        printf("Received message from server: %s\n", buffer);
    }
}

int main() {
    int sock, choice;  // Socket descriptor
    struct sockaddr_in server_addr;  // Server address
    char *message, *sender_fingerprint, *public_key;
    EVP_PKEY *recipient_key;

    // Create the socket (IPv4, TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up the server address (IP and port)
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_port = htons(SERVER_PORT);  // Convert port to network byte order
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Server address (localhost)

    // Connect to the server
    //connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    // Send the message to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    public_key = send_hello(sock);
    // need to make this 'Base64Encode(SHA-256(exported RSA public key))'
    sender_fingerprint = public_key;
    // printf("hello");
    get_client_list(sock);
    // printf("%s\n", public_keys[0]);
    printf("Connected to Server\n");
    printf("Options:\n");
    printf("type 1 to send a private message.\n");
    printf("type 2 to send a public message to all.\n");
    scanf("%d", &choice);
    printf("What is your message? (MAX 256 characters)\n");
    message = malloc(sizeof(char) * 256);
    scanf("%s", message);
    if (choice == 1) {
        // TO DO: add logic to receive recipient as user input and locate their public key
        send_chat_message(sock, message, public_keys[0]);
    } else if (choice == 2) {
        // make sender fingerprint an actual fingerprint
        create_public_chat(sock, sender_fingerprint, message);
    }
    // send(sock, message, strlen(message), 0);

    receive_message(sock);

    // Close the socket
    close(sock);

    return 0;
}

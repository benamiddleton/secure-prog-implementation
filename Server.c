/*
CONTRIBUTORS:
Group 37
Alex Rowe
Darcy Lisk
Michael Marzinotto
Ben Middleton
*/

#include "Server2Server.h"
#include "Server2Client.h"
#include "Server.h"
#include <json-c/json.h> // Include the JSON-C header

#define MAX_FILE_SIZE 1024 * 1024 * 10 // Example: max 100MB for a file
#define CHUNK_SIZE 1024                 // Size of each chunk received
#define FILE_TRANSFER_START "file_transfer_start"
#define FILE_TRANSFER_END "file_transfer_end"
#define FILE_NAME "received_file"

Client clients[MAX_CLIENTS];
int client_count = 0;
Server servers[MAX_SERVERS];
int server_count = 0;

char *get_host_addr(void) {
	char hostbuffer[256], *address;
	struct hostent *host_entry;
	int hostname;

	hostname = gethostname(hostbuffer, sizeof(hostbuffer));
	host_entry = gethostbyname(hostbuffer);
	address = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
	return address;
}

void receive_file(int sock, const char* message) {
    char buffer[CHUNK_SIZE];
    char json_buffer[1024]; // Buffer to hold the JSON message
    int json_length;

    // Parse the JSON message
    json_object *file_message = json_tokener_parse(message);
    if (file_message == NULL) {
        perror("Failed to parse JSON");
        return;
    }

    // Extract file name and size from JSON
    const char *filename = json_object_get_string(json_object_object_get(file_message, "file_name"));
    long file_size = json_object_get_int64(json_object_object_get(file_message, "file_size"));

    // Possible Denial of Service attack - Secure code
    if (file_size >= 10000) {
        printf("File size is too large.\n");
        fflush(stdout);
        // Create an error message
        const char *error_message = "Error: File size exceeds the allowed limit.";

        // Send the error message to the client
        send(sock, error_message, strlen(error_message), 0);

        return;*/
    }

     printf("Receiving file: %s, Size: 2987 bytes\n", filename, file_size);

    FILE *file = fopen(filename, "wb"); // Use the received filename
    if (file == NULL) {
        perror("Failed to open file");
        json_object_put(file_message); // Clean up JSON object
        return;
    }

    ssize_t bytes_received;
    //printf("Starting file reception...\n");

    // Receive file data in chunks
    long total_bytes_received = 0;
    while ((bytes_received = recv(sock, buffer, CHUNK_SIZE, 0)) > 0) {
        fwrite(buffer, sizeof(char), bytes_received, file);
        total_bytes_received += bytes_received;

        // Optional: Print progress
        if (total_bytes_received % (CHUNK_SIZE * 10) == 0) {
            printf("Received %ld bytes...\n", total_bytes_received);
        }
    }

    if (bytes_received < 0) {
        perror("Failed to receive file");
    }

    fclose(file);
    printf("File saved as: %s\n", filename);

    // Clean up the JSON object
    json_object_put(file_message);
}


// Function to handle individual connections
void *handle_incoming_connection(void *input_sock) {
    int sock = *(int *)input_sock;
    int recv_result;
    char message[1000];

   while ((recv_result = recv(sock, message, sizeof(message), 0)) > 0) {

    //printf("Received message: %s\n", message);

    // Check if the message has a "data" field
    char *data_field = extract_field(message, "data");
    char *type_field = NULL;

    if (data_field != NULL) {
        // The message has a "data" field, extract "type" from "data"
        type_field = extract_field(data_field, "type");
    } else {
        // The message has no "data" field, extract "type" directly from the top level
        type_field = extract_field(message, "type");
    }

    // Now check the "type" field and process the message
    if (type_field == NULL) {
        printf("Error: 'type' field is NULL.\n");
    } else if (strcmp(type_field, "signed_data") == 0) {
        //printf("SIGNED");
        //fflush(stdout);
        process_client_message(sock, message);
    } else if (strcmp(type_field, "client_list_request") == 0) {
        //printf("LISTREQUEST");
        //fflush(stdout);
        process_client_list_request(sock);
    } else if (strcmp(type_field, "public_chat") == 0) {
        //printf("PUBLIC");
        //fflush(stdout);
        process_client_message(sock, message);
    } else if (strcmp(type_field,  "hello") == 0) {
        //printf("HELLORECEIVED");
        //fflush(stdout);
        process_client_message(sock, message);
    } else if (strcmp(type_field, "client_update_request") == 0) {
        printf("Client has requested an update request. \n");
        fflush(stdout);
        process_client_update_request(sock);
    } else if (strcmp(type_field, "file_transfer") == 0) {
            // Call receive_file to handle the file transfer
            printf("Received file transfer request.\n");
            receive_file(sock, message); // Ensure that receive_file is correctly defined
    } else {
        printf("Unknown message type: %s\n", type_field);
    }
}


    if (recv_result < 0) {
        perror("receive message from socket failed");
    }
    // Close the socket when the client disconnects
    close(sock);
    free(input_sock);
    return NULL;
}

// Function to manage incoming connections
void manage_incoming_connections(int server_sock) {
    struct sockaddr_in conn_addr;
    socklen_t addr_len = sizeof(conn_addr);
    int *sock = malloc(sizeof(int));
    int new_conn_sock;
    listen(server_sock, SOMAXCONN);

    while (1) {
        if ((new_conn_sock = accept(server_sock, (struct sockaddr *)&conn_addr, &addr_len)) < 0) {
            perror("Failed to accept client connection");
            free(sock);
            continue;
        }        

        // Create a thread to handle the new client
        printf("Client connected successfully\n");
        fflush(stdout);
        pthread_t conn_thread;
        *sock = new_conn_sock;
        if (pthread_create(&conn_thread, NULL, handle_incoming_connection, sock) != 0) {
            perror("Failed to create thread for new client");
            //handle_incoming_connection(sock);
            close(new_conn_sock);
            free(sock);
        } else {
            pthread_detach(conn_thread);
        }
    }
}

int main() {

    initialize_client_count();

    int sock; // Server socket descriptor. Moved client socket to Client struct
    struct sockaddr_in server_addr; // Server address structure

    // Create the socket (IPv4, TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);
    printf("Socket successfully created\n");
    fflush(stdout);

    // Set up the server address (IP and port)
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_port = htons(SERVER_PORT);  // Convert port to network byte order
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to any available network interface

    // Bind the socket to the specified port and IP
    bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    printf("Socket successfully binded to port number: %d\n", SERVER_PORT);
    fflush(stdout);

    //connect_to_neighbour(sock);
    //printf("after neighbour");
    //fflush(stdout);

    manage_incoming_connections(sock);
    printf("after manage");
    fflush(stdout);

    // Close the client and server sockets
    close(sock);

    return 0;
}

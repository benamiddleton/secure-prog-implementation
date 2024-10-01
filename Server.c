#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <pthread.h>
#include <unistd.h>  // For close() function
#include <json-c/json.h>
#include "Server2Server.h"
#include "Server2Client.h"

#define SERVER_PORT 8080  // Port to listen on
#define BUFFER_SIZE 1024

typedef struct {
    int server_socket;
    int incoming_socket;
} sockets;

// Function to handle individual connections
void *handle_incoming_connection(void *input_socks) {
    sockets *socks = input_socks;
    char message[BUFFER_SIZE];

    // Receive messages from the client
    while (recv(socks->incoming_socket, message, sizeof(message), 0) > 0) {
        // Process each message received from the client
        if (strcmp(extract_field(message, "type"), "signed_data") == 0) {
            process_client_message(socks->incoming_socket, message);
        } else if (strcmp(extract_field(message, "type"), "client_list_request") == 0)  {
            get_neighbourhood_clients(socks->server_socket);
        }
    }

    // Close the socket when the client disconnects
    close(socks->incoming_socket);
    free(socks);
    return NULL;
}

// Function to manage incoming connections
void manage_incoming_connections(int server_sock) {
    struct sockaddr_in conn_addr;
    socklen_t addr_len = sizeof(conn_addr);
    sockets *socks = malloc(sizeof(sockets));
    int new_conn_sock;
    listen(server_sock, 128);

    while (1) {
        if ((new_conn_sock = accept(server_sock, (struct sockaddr *)&conn_addr, &addr_len)) < 0) {
            perror("Failed to accept client connection");
            free(socks);
            continue;
        }        

        // Create a thread to handle the new client
        pthread_t conn_thread;
        socks->server_socket = server_sock;
        socks->incoming_socket = new_conn_sock;
        if (pthread_create(&conn_thread, NULL, handle_incoming_connection, &socks) != 0) {
            perror("Failed to create thread for new client");
            close(new_conn_sock);
            free(socks);
        } else {
            pthread_detach(conn_thread);
        }
    }
}

int main() {
    int sock; // Server socket descriptor. Moved client socket to Client struct
    struct sockaddr_in server_addr; // Server address structure

    // Create the socket (IPv4, TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // Set up the server address (IP and port)
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_port = htons(SERVER_PORT);  // Convert port to network byte order
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to any available network interface

    // Bind the socket to the specified port and IP
    bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    // connect_to_neighbour(sock);

    manage_incoming_connections(sock);

    // Close the client and server sockets
    close(sock);

    return 0;
}

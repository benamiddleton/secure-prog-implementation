#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function
#include "Server2Server.h"
#include "Server2Client.h"

#define SERVER_PORT 8080  // Port to listen on

int main() {
    int sock, ; // Server socket descriptor. Moved client socket to Client struct
    struct sockaddr_in server_addr; // Server address structure

    // Create the socket (IPv4, TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // Set up the server address (IP and port)
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_port = htons(SERVER_PORT);  // Convert port to network byte order
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to any available network interface

    // Bind the socket to the specified port and IP
    bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    connect_to_neighbour(sock);

    manage_clients(sock);

    // Close the client and server sockets
    close(sock);

    return 0;
}

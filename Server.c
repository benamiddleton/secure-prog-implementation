#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function

#define SERVER_PORT 8080  // Port to listen on

int main() {
    int sock, client_sock;  // Server and client socket descriptors
    struct sockaddr_in server_addr, client_addr;  // Server and client address structures
    char buffer[256];  // Buffer to receive data

    // Create the socket (IPv4, TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // Set up the server address (IP and port)
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_port = htons(SERVER_PORT);  // Convert port to network byte order
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to any available network interface

    // Bind the socket to the specified port and IP
    bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    // Listen for incoming connections
    listen(sock, 3);

    // Accept a client connection
    socklen_t client_addr_size = sizeof(client_addr);
    client_sock = accept(sock, (struct sockaddr *)&client_addr, &client_addr_size);

    // Receive a message from the client
    recv(client_sock, buffer, sizeof(buffer), 0);
    printf("Received message: %s\n", buffer);

    // Close the client and server sockets
    close(client_sock);
    close(sock);

    return 0;
}

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function

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

    // Close the socket
    close(sock);

    return 0;
}


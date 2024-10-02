#include "Server2Server.h"
#include "Server2Client.h"
#include "Server.h"

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

// Function to handle individual connections
void *handle_incoming_connection(void *input_sock) {
    int sock = *(int *)input_sock;
    int recv_result;
    char message[BUFFER_SIZE];

    // Receive messages from the client
    while ((recv_result = recv(sock, message, sizeof(message), 0)) > 0) {
        // Process each message received from the client
        if (strcmp(extract_field(message, "type"), "signed_data") == 0) {
            process_client_message(sock, message);
        } else if (strcmp(extract_field(message, "type"), "client_list_request") == 0)  {
            process_client_list_request(sock);
        } else if (strcmp(extract_field(extract_field(message, "data"), "type"), "server_hello") == 0)  {
            process_server_hello_received(sock, extract_field(extract_field(message, "data"),"sender"));
        } else if (strcmp(extract_field(message, "type"), "client_update_request") == 0) {
            process_client_update_request(sock);
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
        printf("Client connected");
        fflush(stdout);
        pthread_t conn_thread;
        *sock = new_conn_sock;
        if (pthread_create(&conn_thread, NULL, handle_incoming_connection, sock) != 0) {
            perror("Failed to create thread for new client");
            close(new_conn_sock);
            free(sock);
        } else {
            pthread_detach(conn_thread);
        }
    }
}

int main() {
    printf("1 socket");
    fflush(stdout);
    int sock; // Server socket descriptor. Moved client socket to Client struct
    struct sockaddr_in server_addr; // Server address structure
    printf("2 socket");
    fflush(stdout);

    // Create the socket (IPv4, TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);
    printf("after socket");
    fflush(stdout);

    // Set up the server address (IP and port)
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_port = htons(SERVER_PORT);  // Convert port to network byte order
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to any available network interface

    // Bind the socket to the specified port and IP
    bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    printf("after bind");
    fflush(stdout);

    connect_to_neighbour(sock);

    manage_incoming_connections(sock);
    printf("after manage");
    fflush(stdout);

    // Close the client and server sockets
    close(sock);

    return 0;
}

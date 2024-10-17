#include "Server2Server.h"
#include "Server2Client.h"
#include "Server.h"

#define MAX_FILE_SIZE 1024 * 1024 * 10 // Example: max 100MB for a file
#define CHUNK_SIZE 1024                 // Size of each chunk received
#define FILE_TRANSFER_START "file_transfer_start"
#define FILE_TRANSFER_END "file_transfer_end"
#define FILE_NAME "received_file.bin"

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

// Function to receive file from the client
void receive_file(int sock) {
    char buffer[CHUNK_SIZE];
    FILE *file = fopen(FILE_NAME, "wb"); // Open file to write binary data

    if (file == NULL) {
        perror("Failed to open file");
        return;
    }

    ssize_t bytes_received;
    printf("Starting file reception...\n");

    // Receive file data in chunks
    while ((bytes_received = recv(sock, buffer, CHUNK_SIZE, 0)) > 0) {
        fwrite(buffer, sizeof(char), bytes_received, file);

        // Check if the client sent end of file signal
        if (strstr(buffer, FILE_TRANSFER_END) != NULL) {
            printf("File transfer completed.\n");
            break;
        }
    }

    if (bytes_received < 0) {
        perror("Failed to receive file");
    }

    fclose(file);
    printf("File saved as: %s\n", FILE_NAME);
}

// Function to handle individual connections
void *handle_incoming_connection(void *input_sock) {
    int sock = *(int *)input_sock;
    int recv_result;
    char message[10000];

    //printf("start of handle");

    // Receive messages from the client
    /*while ((recv_result = recv(sock, message, sizeof(message), 0)) > 0) {
        printf("PLEASEWORK");
        fflush(stdout);
        printf("Received message: %s\n", message);
        printf("DIDITWORK");
        fflush(stdout);
        // Process each message received from the client
        if (strcmp(message, FILE_TRANSFER_START) == 0) { // Check for file transfer start
            printf("File transfer initiated.\n");
            receive_file(sock); // Call function to receive file
        } else if (strcmp(extract_field(message, "type"), "signed_data") == 0) {
            printf("SIGNED");
            fflush(stdout);
            process_client_message(sock, message);
        } else if (strcmp(extract_field(message, "type"), "client_list_request") == 0)  {
            printf("LISTREQUEST");
            fflush(stdout);
            process_client_list_request(sock);
        } else if (strcmp(extract_field(extract_field(message, "data"), "type"), "server_hello") == 0)  {
            printf("HELLORECEIVED");
            fflush(stdout);
            process_server_hello_received(sock, extract_field(extract_field(message, "data"),"sender"));
        } else if (strcmp(extract_field(message, "type"), "client_update_request") == 0) {
            printf("UPDATEREQUEST");
            fflush(stdout);
            process_client_update_request(sock);
        } else if (strcmp(extract_field(extract_field(message, "data"), "type"), "public_chat") == 0) {
            printf("PUBLIC");
            fflush(stdout);
            process_client_message(sock, message);
        } else {printf("NOTWORKING");}
    }*/

   while ((recv_result = recv(sock, message, sizeof(message), 0)) > 0) {
    printf("PLEASEWORK");
    fflush(stdout);
    printf("Received message: %s\n", message);
    printf("DIDITWORK");
    fflush(stdout);

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
        printf("SIGNED");
        fflush(stdout);
        process_client_message(sock, message);
    } else if (strcmp(type_field, "client_list_request") == 0) {
        printf("LISTREQUEST");
        fflush(stdout);
        process_client_list_request(sock);
    } else if (strcmp(type_field, "public_chat") == 0) {
        printf("PUBLIC");
        fflush(stdout);
        process_client_message(sock, message);
    } else if (strcmp(type_field,  "hello") == 0) {
        printf("HELLORECEIVED");
        fflush(stdout);
        //process_server_hello_received(sock, extract_field(data_field, "sender"));   // NOT SURE OF THIS LINE???
        process_client_message(sock, message);
    } else if (strcmp(type_field, "client_update_request") == 0) {
        printf("UPDATEREQUEST");
        fflush(stdout);
        process_client_update_request(sock);
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
        printf("Client connected");
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

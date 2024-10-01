#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function
#include <fcntl.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <netdb.h>
#include <pthread.h>

json_object *get_neighbourhood_clients(int socket) {

}

char *get_host_addr(void) {
	char hostbuffer[256], *address;
	struct hostent *host_entry;
	int hostname;

	hostname = gethostname(hostbuffer, sizeof(hostbuffer));
	host_entry = gethostbyname(hostbuffer);
	address = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
	return address;
}

void server_hello(int socket) {
	char *message, *address;
	json_object *message_json = json_object_new_object();
	json_object *data_json = json_object_new_object();
	
	address = get_host_addr();
	message = malloc(sizeof(char) * 128);
	json_object_object_add(data_json, "type", json_object_get_string("server_hello"));
	json_object_object_add(data_json, "sender", json_object_get_string(address));
	json_object_object_add(message_json, "data", data_json);
	message = json_object_to_json_string(message_json);
	send(socket, message, strlen(message), 0);
}

void *handle_server_to_server(void *sock) {
	int socket = *(int *)sock;
	server_hello(socket);

	close(socket);
	free(sock);
	return NULL;
}

int connect_to_neighbour(int socket) {
	int file, dest_port, dest_addr_len, dest_port_len;
	char *servers, *server, *dest_address, *dest_port_str;
	struct sockaddr_in dest_sock;

	file = open("server_list.txt", O_RDWR);
	servers = malloc(sizeof(char) * 256);
	if (read(file, servers, 256) == -1) {
		perror("server_list.txt read failed");
		return 1;
	}
	
	server = strtok(servers, "\n");
	while (server != NULL) {
		dest_address = malloc(sizeof(char) * 32);
		dest_port_str = malloc(sizeof(char) * 16);
		dest_addr_len = strchr(server,':') - server;
		strncpy(dest_address, server, dest_addr_len);
		dest_port_len = strlen(server) - dest_addr_len - 1;
		strncpy(dest_port_str, strchr(server, ':')+1, dest_port_len);
		if (dest_port_str == NULL) {
			dest_port = 443;
		} else {
			dest_port = atoi(dest_port_str);
		}
		dest_sock.sin_family = AF_INET;  // IPv4
		dest_sock.sin_port = htons(dest_port);  // Convert port to network byte order
		dest_sock.sin_addr.s_addr = inet_addr(dest_address);  // Server address (localhost)
		connect(socket, (struct sockaddr *)&dest_sock, sizeof(dest_sock));

		pthread_t server_thread;
		int *server_socket = malloc(sizeof(int));
		*server_socket = socket;
		if (pthread_create(&server_thread, NULL, handle_server_to_server, server_socket) != 0) {
			perror("Failed to create thread for new server to server connection");
			close(socket);
			free(server_socket);
		} else {
			pthread_detach(server_thread);
		}
		free(dest_address);
		free(dest_port_str);
		server = strtok(NULL,"\n");
	}
	
	return 0;
}
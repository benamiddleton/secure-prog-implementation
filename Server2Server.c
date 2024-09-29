#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function
#include <fcntl.h>
#include <stdlib.h>
#include <netdb.h>

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
	
	address = get_host_addr();
	message = malloc(sizeof(char) * 128);
	strncpy(message, "{\"data\":{\"type\":\"server_hello\",\"sender\":\"", 44);
	strncat(message, address, strlen(address));
	strncat(message, "\"}}", 4);
	send(socket, message, strlen(message), 0);
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
		server_hello(socket);
		server = strtok(NULL,"\n");
	}
	
	return 0;
}
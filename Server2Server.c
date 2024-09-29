#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function
#include <fcntl.h>

void server_hello(char *address, int socket) {
	char *message = malloc(sizeof(char) * 128);

	strncpy(message, "{\"data\":{\"type\":\"server_hello\",\"sender\":\"", 44);
	strncat(message, address, strlen(address));
	strncat(message, "\"}}", 3);
	send(socket, message, strlen(message), 0);
}

void connect_to_neighbour(int socket) {
	int file, dest_port;
	char *servers, *server, *dest_address, *dest_port_str;
	struct sockaddr_in dest_sock;

	file = open("server_list.txt", O_RDWR);
	servers = malloc(sizeof(char) * 256);
	if (read(file, servers, 256) == -1) {
		perror("server_list.txt read failed");
		return 1;
	}
	server = strtok(servers, '\n');
	while (server != NULL) {
		dest_address = strtok(server, ':');
		dest_port_str = strtok(server, ':');
		if (dest_port_str == NULL) {
			dest_port = 443;
		} else {
			dest_port = atoi(dest_port_str);
		}
		dest_sock.sin_family = AF_INET;  // IPv4
		dest_sock.sin_port = htons(dest_port);  // Convert port to network byte order
		dest_sock.sin_addr.s_addr = inet_addr(dest_address);  // Server address (localhost)
		connect(socket, (struct sockaddr *)&dest_sock, sizeof(dest_sock));
		server_hello(dest_address, socket);
	}
	
}
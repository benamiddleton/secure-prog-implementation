/*
CONTRIBUTORS:
Group 37
Alex Rowe
Darcy Lisk
Michael Marzinotto
Ben Middleton
*/

#include "Server.h"


Server *add_server(int server_sock, const char* address, int port) {
    if (server_count < MAX_SERVERS) {
        servers[server_count].socket = server_sock;
        strncpy(servers[server_count].address, address, sizeof(servers[server_count].address));
        servers[server_count].port = port;
        server_count++;
        return &servers[server_count-1];
    }
    printf("Max server connection limit reached\n");
	return NULL;
}

// Find a server by socket
Server* find_server(int server_sock) {
    for (int i = 0; i < server_count; i++) {
        if (servers[i].socket == server_sock) {
            return &servers[i];
        }
    }
    return NULL;
}

void process_client_update_request(int socket) {
	json_object *update_json, *client_public_keys;
	char *message;

	update_json = json_object_new_object();
	json_object_object_add(update_json, "type", json_object_new_string("client_update"));
	client_public_keys = json_object_new_array();
	for (int i=0;i<client_count;i++) {
		json_object_array_add(client_public_keys, json_object_new_string(clients[i].public_key));
	}
	json_object_object_add(update_json, "clients", client_public_keys);
	send(socket, message, strlen(message), 0);
}

json_object *get_server_clients(Server *server) {
	json_object *message_json, *response_json, *clients_array;
	char *message, *buffer;

	message_json = json_object_new_object();
	json_object_object_add(message_json, "type", json_object_new_string("client_update_request"));
	message = json_object_to_json_string(message_json);
	send(server->socket, message, strlen(message), 0);
	buffer = malloc(sizeof(char) * BUFFER_SIZE);
	recv(server->socket, buffer, sizeof(buffer), 0);
	response_json = json_tokener_parse(buffer);
	json_object_object_get_ex(response_json, "clients", &clients_array);
	server->server_client_count = json_object_array_length(clients_array);
	for (int i=0;i<server->server_client_count;i++) {
		json_object *element = json_object_array_get_idx(clients_array, i);
		char *public_key = json_object_get_string(element);
		strcpy(server->clients[i], public_key);
	}
}

void process_server_hello_received(int socket, const char* sender) {
	add_server(socket, sender, 0);
}

void server_hello(int socket) {
	char *message, *address, *alloc_message;
	json_object *message_json = json_object_new_object();
	json_object *data_json = json_object_new_object();
	
	address = get_host_addr();
	message = malloc(sizeof(char) * 128);
	json_object_object_add(data_json, "type", json_object_get_string("server_hello"));
	json_object_object_add(data_json, "sender", json_object_get_string(address));
	json_object_object_add(message_json, "data", data_json);
	message = json_object_to_json_string(message_json);
	alloc_message = strdup(message);
	send(socket, alloc_message, strlen(alloc_message), 0);
}

void handle_server_to_server(Server *server) {
	server_hello(server->socket);
	get_server_clients(server);
}

int connect_to_neighbour(int sock) {
	int file, dest_port, dest_addr_len, dest_port_len, dest_sock;
	char *servers, *server, *dest_address, *dest_port_str;
	struct sockaddr_in dest_sock_addr;
	Server *conn_server;

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
		dest_sock = socket(AF_INET, SOCK_STREAM, 0);
		dest_sock_addr.sin_family = AF_INET;  // IPv4
		dest_sock_addr.sin_port = htons(dest_port);  // Convert port to network byte order
		dest_sock_addr.sin_addr.s_addr = inet_addr(dest_address);  // Server address (localhost)
		connect(dest_sock, (struct sockaddr *)&dest_sock_addr, sizeof(dest_sock_addr));

		conn_server = add_server(dest_sock, dest_address, dest_port);
		handle_server_to_server(conn_server);
		free(dest_address);
		free(dest_port_str);
		server = strtok(NULL,"\n");
	}
	
	return 0;
}
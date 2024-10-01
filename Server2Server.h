#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // For socket functions and address structures
#include <unistd.h>  // For close() function
#include <fcntl.h>

void connect_to_neighbour(int);
json_object *get_neighbourhood_clients(int);
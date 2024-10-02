READ ME - SECURE PROGRAMMING PROJECT IMPLEMENTATION

CONTRIBUTORS:

Alex Rowe
Darcy Lisk
Michael Marzinotto
Ben Middleton

PROJECT HAS INTENTIONAL BACKDOORS LEFT IN AS THIS IS A SECURE PROGRAMMING PROJECT

CONTENTS:
Client.c
Handles client interface and sends and receives messages from server

Encryption.c
Encryption.h
Handles encryption and message verification

README.md
Server.c
Puts together all server operations

Server2Client.c
Server2Client.h
Handles server client interactions including routing of messages and connecting to client

Server2Server.c
Server2Server.h
Handles server to server interactions including maintaining the neighbourhood protocol

server_list.txt

DEPENDENCIES:
Ensure you have the following libraries installed:
OpenSSL - sudo apt-get install openssl libssl-dev
Json-c - sudo apt-get install libjson-c-dev



COMPILATION COMMAND:
Compile using the following makefile commands:
Make server
Make client
USAGE:
Run the server in a terminal using:
./server_app
Run the client in a separate terminal using: 
./client_app
The client connects to the server and can send messages. The server processes incoming messages and routes them to the appropriate clients. Messages are encrypted, signed, and formatted as JSON objects.
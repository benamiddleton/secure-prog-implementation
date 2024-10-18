server:
	gcc -w -o server_app Server.c Server2Client.c Server2Server.c Encryption.c -lssl -lcrypto -ljson-c

client:
	gcc -w -o client_app Client.c Encryption.c -lwebsockets -lssl -lcrypto -ljson-c
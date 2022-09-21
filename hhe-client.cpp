#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string>
#include <unistd.h>

#include <iostream>
#include <sstream>

using namespace std;

int main (int argc, const char * argv[]){
    
    int clientSocket, new_connection;
	struct sockaddr_in server;

    char client_message[4096], server_reply[4096];

    //create socket
	clientSocket = socket(AF_INET, SOCK_STREAM, 0);

	if (clientSocket == -1) {
        cerr << "Not able to create the Socket" << endl;
        return -1;
    }

    //initialize connection parameters
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(5000);

    if (connect(clientSocket, (struct sockaddr *)&server, sizeof(server)) < 0){
		cerr << "Not able to connect to Server" << endl;
        return -1;
	} 

    send(clientSocket, "Testing out the Socket ", 40, 0);

    close(clientSocket);
    return 0;



}
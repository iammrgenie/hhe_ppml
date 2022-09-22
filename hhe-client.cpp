#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string>
#include <unistd.h>

#include <iostream>
#include <sstream>

#include <seal/seal.h>
#include "sealhelper.h"

using namespace std;
using namespace seal;

stringstream parms_stream;
stringstream data_stream;
stringstream sk_stream;

string convertChar2String(char* in) {
    string out(in);
    return out;
}

int main (int argc, const char * argv[]){
    
    int clientSocket, new_connection;
	struct sockaddr_in server;

    //char client_message[4096], server_reply[4096];
    char TestRecv[82];

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

    cout << "[Client] Connected to Server\n";

    cout << "[Client] Receiving Encryption Parameters\n";
    string s;
    int n;
    
    while ((n = recv(clientSocket, TestRecv, sizeof(TestRecv), 0)) > 0 )
        s.append(TestRecv, TestRecv + n);

    cout << s << endl;

    data_stream << s;

    EncryptionParameters parms;
    parms.load(data_stream);
    SEALContext context(parms);

    print_parameters(context);
   
    close(clientSocket);
    return 0;



}
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string>
#include <unistd.h>

#include <iostream>
#include <sstream>

#include "pasta_3_seal.h"
#include "sealhelper.h"
#include "SEAL_Cipher.h"
#include "pasta_3_plain.h"  // for PASTA_params

using namespace std;
using namespace seal;

stringstream parms_stream;
stringstream data_stream;
stringstream pk_stream;

static const bool USE_BATCH = true;


int main (int argc, const char * argv[]){
    seal::sec_level_type sec = seal::sec_level_type::tc128;
    
    int clientSocket, new_connection;
	struct sockaddr_in server;

    //char client_message[4096], server_reply[4096];
    char parms_char[102];

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
    string parms_string;
    int n;
    
    while ((n = recv(clientSocket, parms_char, sizeof(parms_char), 0)) > 0 )
        parms_string.append(parms_char, parms_char + n);

    
    //Deserialize from String to SEAL object
    parms_stream << parms_string;

    EncryptionParameters parms;
    parms.load(parms_stream);
    SEALContext context(parms);

    print_parameters(context);
   
    close(clientSocket);
    return 0;



}
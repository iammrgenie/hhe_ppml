#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <sstream>

#include <seal/seal.h>
#include "sealhelper.h"

using namespace std;
using namespace seal;

#define PORT 5000

stringstream parms_stream;
stringstream data_stream;
stringstream sk_stream;

int main (int argc, const char * argv[]){

    //SEAL Parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 50}));

    SEALContext context(parms);
    print_parameters(context);
    cout << "\n";

    auto size = parms.save(parms_stream);

    string test = parms_stream.str();

    cout << "EncryptionParameters: wrote " << size << " bytes" << endl;

    char TestSend[size+1];
    strcpy(TestSend, test.c_str());
    
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(PORT);

    //Client variables
    struct sockaddr_in caddr;
    socklen_t caddrSize = sizeof(caddr);
    int socketClient;

    int option = 1;
    int saddrSize = sizeof(saddr);
    int socketServer = socket(AF_INET, SOCK_STREAM, 0);   //SOCK_STREAM makes use of TCP

    setsockopt(socketServer, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option));

    if (socketServer == -1) {
        std::cerr << "Not able to create the Socket" << std::endl;
        return -1;
    }

    //Bind socket to IP address
    bind(socketServer, (struct sockaddr*)&saddr, sizeof(saddr));

    //Listen for Connections on specified PORT
    listen(socketServer, SOMAXCONN);
    std::stringstream ss;
    ss << PORT;
    std::cout << "[Server] listening on port " << ss.str() << std::endl;

    char buff[4096];

    int sizeBytesReceived;

    //loop while waiting for connection
    while (true) {
        //Accept connections from Clients
        socketClient = accept(socketServer, (struct sockaddr *)&caddr, (socklen_t *)&caddrSize);
        std::cout << "[Server] Client connected successfully " << std::endl;

        char hostClient[NI_MAXHOST];
        char portClient[NI_MAXSERV];
        memset(hostClient, 0, NI_MAXHOST);
        memset(portClient, 0, NI_MAXSERV);

        // Retrieve client connection details
        if (getnameinfo((sockaddr *)&caddr, sizeof(caddr), hostClient, NI_MAXHOST, portClient, NI_MAXSERV, 0) == 0) {
            std::cout << " --> " << hostClient << " connected to port " << portClient << std::endl; 
        } else {
            inet_ntop(AF_INET, &caddr.sin_addr, hostClient, NI_MAXHOST);
            std::cout << " --> " << hostClient << " connected to port " << ntohs(caddr.sin_port) << std::endl;
        }

        //Receive or Send data 
        cout << "[Server] Sending Encryption Parameters\n";
        send(socketClient, "Test Receive", 20, 0);

        close(socketClient);
    }


    return 0;

}
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

string convertChar2String(char* in) {
    string out(in);
    return out;
}


int main (int argc, const char * argv[]){

    //Set the Hybrid Homorphic Parameters
  	uint64_t plain_mod = 65537;
  	uint64_t mod_degree = 16384;
  	int seclevel = 128;

    if (seclevel != 128) throw runtime_error("Security Level not supported");
    seal::sec_level_type sec = seal::sec_level_type::tc128;

    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(mod_degree);

    if (mod_degree == 65536) {
        sec = seal::sec_level_type::none;
        parms.set_coeff_modulus(
            {0xffffffffffc0001, 0xfffffffff840001, 0xfffffffff6a0001,
             0xfffffffff5a0001, 0xfffffffff2a0001, 0xfffffffff240001,
             0xffffffffefe0001, 0xffffffffeca0001, 0xffffffffe9e0001,
             0xffffffffe7c0001, 0xffffffffe740001, 0xffffffffe520001,
             0xffffffffe4c0001, 0xffffffffe440001, 0xffffffffe400001,
             0xffffffffdda0001, 0xffffffffdd20001, 0xffffffffdbc0001,
             0xffffffffdb60001, 0xffffffffd8a0001, 0xffffffffd840001,
             0xffffffffd6e0001, 0xffffffffd680001, 0xffffffffd2a0001,
             0xffffffffd000001, 0xffffffffcf00001, 0xffffffffcea0001,
             0xffffffffcdc0001, 0xffffffffcc40001});  // 1740 bits
    } else {
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(mod_degree));
    }
    parms.set_plain_modulus(plain_mod);
    auto context = make_shared<seal::SEALContext>(parms, true, sec);

    print_parameters(context);
    cout << "\n";

    auto size = parms.save(parms_stream);

    string test = parms_stream.str();
    cout << "EncryptionParameters: wrote " << size << " bytes" << endl;
    
    //Server Parameters
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(PORT);

    //Connecting Client Parameters
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
        send(socketClient, test.data(), size+1, 0);

        // Test conversion and deserialization
        //string outTest = convertChar2String(TestSend);
        //cout << "Output String " << outTest;

        /*
        sk_stream << outTest;

        EncryptionParameters parms2;
        parms2.load(sk_stream);
        SEALContext context2(parms2);

        print_parameters(context2);
        */

        close(socketClient);
    }


    return 0;

}
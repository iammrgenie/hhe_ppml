#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <sstream>

#include "src/pasta_3_seal.h"
#include "src/sealhelper.h"
#include "src/SEAL_Cipher.h"
#include "src/pasta_3_plain.h"  // for PASTA_params
#include "src/sealhelper.h"

using namespace std;
using namespace seal;

static const bool USE_BATCH = true;

#define PORT 5000

stringstream parms_stream;
stringstream data_stream;
stringstream pk_stream;
stringstream sk_stream;

struct commData {
    vector<uint64_t> x_i;
    vector<uint64_t> c_i;
    vector<Ciphertext> c_1;
    vector<Ciphertext> c_2;
    vector<uint64_t> x_p;
};

void sendKeyData(string &inStr, size_t len, int sockServ) {
    int numParts = 21;

    //Split into 2

    for (int i = 0; i < numParts; i ++){
        if (i = 20) {
            string part = inStr.substr(((i * 50000) + 1), (len - (500000*20)));
            cout << "Size of Data: " << sizeof(part) << endl;
        } else {
            string part = inStr.substr(((i * 50000) + 1), ((i + 1) * 50000));
            cout << "Size of Data: " << sizeof(part) << endl;
        }
    }

    // //Split into 2
    // part1 = inStr.substr(0, 80000);
    // part2 = inStr.substr(80001, len);

    // cout << "[Server] Sending Key to Connected Client\n";
    // send(sockServ, part1.data(), 80000, 0);
    // send(sockServ, part2.data(), sizeof(part2), 0);

}

int main (int argc, const char * argv[]){
    commData Server1;

    //Set the SEAL Homorphic Parameters
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
   
    SEALContext context(parms);

    print_parameters(parms);

    //Convert Encryption parameters to a string for communication
    auto size = parms.save(parms_stream);
    string parms_string = parms_stream.str();
    
    cout << "[Server] Encryption Parameters: wrote " << size << " bytes" << endl;

    //Use Encryption Parameters for the Analyst
    KeyGenerator keygen(context);
    SecretKey he_sk = keygen.secret_key();      //HE Decryption Key
    Serializable<PublicKey> he_pk = keygen.create_public_key();
    


    //Save and send HE public key
    auto pk_size = he_pk.save(pk_stream);
    string pk_string = pk_stream.str();

    //Save and send HE secret key
    auto sk_size = he_sk.save(sk_stream);
    string sk_string = sk_stream.str();
    
    cout << "[Server] Public Key: wrote " << pk_size << " bytes" << endl;
    cout << "[Server] Secret Key: wrote " << sk_size << " bytes" << endl;

    
    //Socket Communication Section
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

        //Send the Encryption Parameters
        cout << "[Server] Sending Encryption Parameters to Connected Client\n";
        send(socketClient, parms_string.data(), size + 1, 0);

        char key_length[10];
        sprintf(key_length, "%ld", sk_size);
        //cout << "[Server] Size of Key = " << key_length << endl;

        send(socketClient, key_length, sizeof(key_length) + 1, 0);

        sendKeyData(pk_string, pk_size, socketClient);
        
        //Send the Key
        // cout << "[Server] Sending Key to Connected Client\n";
        // send(socketClient, sk_string.data(), sk_size, 0);

        // data_stream << pk_string;

        // PublicKey pknew;
        // pknew.load(con1, data_stream);


        close(socketClient);
    }


    return 0;

}
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <sstream>

//using namespace std;

#define PORT 5000

int main (int argc, const char * argv[]){
    
    struct sockaddr_in saddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(PORT)
    };

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
        std::cout << "1" << std::endl;
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
        sizeBytesReceived = recv(socketClient, buff, 4096, 0);
        if (sizeBytesReceived == -1) {
            std::cerr << "Error receiving message. Abort!!!";
            break;
        } else if (sizeBytesReceived == 0) {
            std::cout << "Client Disconnected " << std::endl;
            break;
        }

        //Send Data back to Client
        send(socketClient, buff, sizeBytesReceived + 1, 0);

        std::cout << std::string(buff, 0, sizeBytesReceived) << std::endl;

        close(socketClient);
    }


    return 0;

}
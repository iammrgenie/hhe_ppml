#include <vector>
#include <chrono>
#include <iostream>
#include <string>
#include <typeinfo>

#include "../configs/config.h"
#include "../src/SEAL_Cipher.h"
#include "../src/pasta_3_plain.h"  // for PASTA_params
#include "../src/pasta_3_seal.h"
#include "../src/utils.h"
#include "../src/sealhelper.h"

struct UserData {
    vector<vector<uint64_t>> x;  // plaintext data
    vector<Ciphertext> c_prime;  // HE encrypted data
};


int main() {
    print_example_banner("Performance and Communication Analysis for the User in the 3-Party HE Setup");

    // Create the HE keys
    cout << config::plain_mod << endl;

    // Encrypt the data using HE

    // Decrypt the results


    return 0;
}
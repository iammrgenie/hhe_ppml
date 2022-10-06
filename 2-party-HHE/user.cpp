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

#define NUM_RUN 50 // number of runs to get the average measurements
#define NUM_VEC 10 // number of vectors the user have

static const bool USE_BATCH = true;

struct UserData {
    vector<uint64_t> ssk;  // the secret symmetric keys
    std::vector<Ciphertext> c_k;  // the HE encrypted symmetric keys
    vector<vector<uint64_t>> x;  // plaintext data
    vector<vector<uint64_t>> c;  // symmetric encrypted data
    PublicKey he_pk;
    SecretKey he_sk;
    RelinKeys he_rk;
    GaloisKeys he_gk;
    Ciphertext c_res;  // the HE encrypted result
};


int main() {
    print_example_banner("Performance and Communication Analysis for the User in the 2-Party HHE Setup");

    UserData User;
    // Create the HE keys
    shared_ptr<SEALContext> context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
    KeyGenerator keygen(*context);
    User.he_sk = keygen.secret_key();                                    //HHE Decryption Secret Key
    // keygen.create_public_key(Anal1.he_pk);                                //HHE Encryption Key
    // keygen.create_relin_keys(Anal1.he_rk);                                //HHE RelinKey
    
    // BatchEncoder analyst_he_benc(*context);
    // Encryptor analyst_he_enc(*context, Anal1.he_pk);
    // Evaluator analyst_he_eval(*context);

    // bool use_bsgs = false;
    // vector<int> gk_indices = add_gk_indices(use_bsgs, analyst_he_benc);
    // keygen.create_galois_keys(gk_indices, Anal1.he_gk);  

    // Create the symmetric key

    // Encrypt the symmetric key

    // Symmetrically encrypt the data

    // Decrypt the result


    return 0;
}
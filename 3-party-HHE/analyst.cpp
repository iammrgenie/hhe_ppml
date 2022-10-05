#include <vector>
#include <chrono>
#include <iostream>
#include <string>
#include <typeinfo>

#include "../src/SEAL_Cipher.h"
#include "../src/pasta_3_plain.h"  // for PASTA_params
#include "../src/pasta_3_seal.h"
#include "../src/utils.h"
#include "../src/sealhelper.h"


static const bool USE_BATCH = true;

using namespace std;
using namespace seal;

struct AnalystData {  
    vector<int64_t> w{17, 31, 24, 17};  // dummy weights
    vector<int64_t> b{-5, -5, -5, -5};  // dummy biases
    Ciphertext w_c;  // the encrypted weights
    Ciphertext b_c;  // the encrypted biases
    PublicKey he_pk;
    SecretKey he_sk;
    RelinKeys he_rk;
    GaloisKeys he_gk;
    stringstream pk_stream;
    stringstream rlk_stream;
    stringstream gk_stream;
    stringstream cipher_stream;
};

int main(){
    chrono::high_resolution_clock::time_point st1, st2, end1, end2;
    chrono::milliseconds t1, t2;

    print_example_banner("Performance and Communication Analysis for the Analyst in the 3-Party Setup");

    AnalystData Anal1;

    //Generate the HHE Parameters
    cout << endl; 
    print_line(__LINE__); 
    cout << "\nGeneration of HHE parameters, Context and Encryption Keys" << endl;

    st1 = chrono::high_resolution_clock::now();                          //Start the timer
    
    uint64_t plain_mod = 65537;
    uint64_t mod_degree = 16384;
    int seclevel = 128;
    shared_ptr<SEALContext> context = get_seal_context(plain_mod, mod_degree, seclevel);
    KeyGenerator keygen(*context);
    Anal1.he_sk = keygen.secret_key();                                    //HHE Decryption Secret Key
    keygen.create_public_key(Anal1.he_pk);                                //HHE Encryption Key
    keygen.create_relin_keys(Anal1.he_rk);                                //HHE RelinKey
    
    BatchEncoder analyst_he_benc(*context);
    Encryptor analyst_he_enc(*context, Anal1.he_pk);
    Evaluator analyst_he_eval(*context);

    BatchEncoder analyst_he_benc(*context);
    Encryptor analyst_he_enc(*context, Anal1.he_pk);
    Evaluator analyst_he_eval(*context);
    bool use_bsgs = false;
    vector<int> gk_indices = add_gk_indices(use_bsgs, analyst_he_benc);
    keygen.create_galois_keys(gk_indices, Anal1.he_gk);                   //HHE GaloisKey

    end1 = chrono::high_resolution_clock::now();                          //End the timer
    t1 = chrono::duration_cast<chrono::milliseconds>(end1 - st1);         //Measure the time difference 
    print_parameters(*context);

    // Take the size of the parameters to send over the network
    auto pk_size = Anal1.he_pk.save(Anal1.pk_stream);
    auto rlk_size = Anal1.he_rk.save(Anal1.rk_stream);
    auto gk_size = Anal1.he_gk.save(Anal1.gk_stream);

    //Print out the Sizes
    cout << "\nPublic Key Size: " << pk_size << endl;
    cout << "\nRelin Key Size: " << rk_size << endl;
    cout << "\nGalois Key Size: " << gk_size << endl;


}
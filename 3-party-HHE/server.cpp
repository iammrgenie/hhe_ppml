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

#define AVG 1
#define NUM_VEC 2

static const bool USE_BATCH = true;


using namespace std;
using namespace seal; 

struct ServerData {  
    vector<int64_t> w{17, 31, 24, 17};  // dummy weights
    vector<int64_t> b{-5, -5, -5, -5};  // dummy biases
    Ciphertext w_c;  // the encrypted weights
    Ciphertext b_c;  // the encrypted biases
    PublicKey he_pk;
    SecretKey he_sk;
    RelinKeys he_rk;
    GaloisKeys he_gk;
    stringstream cipher1_stream;
    stringstream cipher2_stream;
};

struct UserData {
    vector<uint64_t> plain;
    vector<uint64_t> symCipher;
    vector<Ciphertext> heCipher;
    vector<int64_t> recP;
};



int main(){
    print_example_banner("Performance and Communication Analysis for the Server in the 3-Party Setup");

    UserData User1[NUM_VEC];
    ServerData Anal1;
    
    size_t parmsT = 0, ciphT = 0;
    size_t encT = 0, decT = 0;
    size_t pkT = 0, rkT = 0, gkT = 0;

    
    
    //Generate the HHE Parameters
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

    bool use_bsgs = false;
    vector<int> gk_indices = add_gk_indices(use_bsgs, analyst_he_benc);
    keygen.create_galois_keys(gk_indices, Anal1.he_gk);                   //HHE GaloisKey

    vector<uint64_t> user_ssk = get_symmetric_key();
    PASTA_3_MODIFIED_1::PASTA SymmetricEncryptor(user_ssk, plain_mod);

    vector<Ciphertext> cK = encrypt_symmetric_key(user_ssk, USE_BATCH, analyst_he_benc, analyst_he_enc);

    for (int j = 0; j < NUM_VEC; j ++){
        User1[j].plain = create_random_vector(4);
        //print_vec(User1[j].plain, User1[j].plain.size(), "Plaintext ");
        User1[j].symCipher = SymmetricEncryptor.encrypt(User1[j].plain);
        print_vec(User1[j].symCipher, User1[j].symCipher.size(), "Ciphertext ");         
    }

    for (int i = 0; i < AVG; i ++){
        chrono::high_resolution_clock::time_point st1, st2, st3, end1, end2, end3;
        chrono::milliseconds diff1, diff2, diff3;

        SecretKey CSP;
        KeyGenerator csp_keygen(*context);
        CSP = csp_keygen.secret_key();   

        PASTA_3_MODIFIED_1::PASTA_SEAL CSPWorker(context, Anal1.he_pk, CSP,Anal1.he_rk, Anal1.he_gk);
        cout << "\n  --------- CSP Cipher Decomposition ------- " << endl;
        
        st1 = chrono::high_resolution_clock::now();                          //Start the timer
        for (int j = 0; j < NUM_VEC; j++){
            cout << "Data #" << j+1 << endl;
            User1[j].heCipher = CSPWorker.decomposition(User1[j].symCipher, cK, USE_BATCH);
        }
        end1 = chrono::high_resolution_clock::now();                          //End the timer
        
        diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - st1);         //Measure the time difference 
        cout << "\n[RES] Ciphertext Decomposition Time for "<< NUM_VEC << " Vectors: " << diff1.count() << " milliseconds" << endl;


    }

    // //Compute the Average communication and computation
    // cout << "[RES] Average Key Generation Time over 50 iterations: " << parmsT / AVG << " milliseconds" << endl;
    // cout << "[RES] Average HE Encryption of Weights and Biases over 50 iterations: " << encT / AVG << " milliseconds" << endl;
    // cout << "[RES] Average HE Decryption of C(res) over 50 iterations: " << decT / AVG << " milliseconds" << endl;
    // cout << "[RES] Average Public Key size over 50 iterations: " << pkT / AVG << " bytes" << endl;
    // cout << "[RES] Average Relin Key size over 50 iterations: " << rkT / AVG << " bytes" << endl;
    // cout << "[RES] Average Galois Key size over 50 iterations: " << gkT / AVG << " bytes" << endl;
    // cout << "[RES] Ciphertext size over 50 iterations: " << ciphT / AVG << " bytes" << endl;



}
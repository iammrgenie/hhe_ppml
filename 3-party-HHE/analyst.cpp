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

#define AVG 50

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
    stringstream rk_stream;
    stringstream gk_stream;
    stringstream cipher1_stream;
    stringstream cipher2_stream;
};

// struct AvgPerformance {
//     chrono::milliseconds parmsT;
//     size_t pk_size;
//     size_t rk_size;
//     size_t gk_size
// };

int main(){
    print_example_banner("Performance and Communication Analysis for the Analyst in the 3-Party Setup");

    // AvgPerformance Test[AVG];
    
    size_t parmsT = 0, ciphT = 0;
    size_t encT = 0, decT = 0;
    size_t pkT = 0, rkT = 0, gkT = 0;


    for (int i = 0; i < AVG; i ++){
        AnalystData Anal1;
        chrono::high_resolution_clock::time_point st1, st2, st3, end1, end2, end3;
        chrono::milliseconds diff1, diff2, diff3;

        //Generate the HHE Parameters
        //print_line(__LINE__); 
        //cout << "Generation of HHE parameters, Context and Encryption Keys" << endl;

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

        bool use_bsgs = false;
        vector<int> gk_indices = add_gk_indices(use_bsgs, analyst_he_benc);
        keygen.create_galois_keys(gk_indices, Anal1.he_gk);                   //HHE GaloisKey

        end1 = chrono::high_resolution_clock::now();                          //End the timer
        diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - st1);         //Measure the time difference 
        //print_parameters(*context);

        //cout << "\nKey Generation Time: " << diff1.count() << " milliseconds" << endl;
        parmsT = parmsT + diff1.count();

        // Take the size of the parameters to send over the network
        auto pk_size = Anal1.he_pk.save(Anal1.pk_stream);
        auto rk_size = Anal1.he_rk.save(Anal1.rk_stream);
        auto gk_size = Anal1.he_gk.save(Anal1.gk_stream);

        pkT = pkT + pk_size;
        rkT = rkT + rk_size;
        gkT = gkT + gk_size;

        //Print out the Sizes
        // cout << "\nPublic Key Size: " << pk_size << endl;
        // cout << "\nRelin Key Size: " << rk_size << endl;
        // cout << "\nGalois Key Size: " << gk_size << endl;

        //cout << "HE Encryption of weights and biases" << endl;
        st2 = chrono::high_resolution_clock::now();                              //Start the timer
        Anal1.w_c = encrypting(Anal1.w, Anal1.he_pk, analyst_he_benc, analyst_he_enc);
        Anal1.b_c = encrypting(Anal1.b, Anal1.he_pk, analyst_he_benc, analyst_he_enc);
        end2 = chrono::high_resolution_clock::now();                             //End the timer
        diff2 = chrono::duration_cast<chrono::milliseconds>(end2 - st2);         //Measure the time difference 
        encT = encT + diff2.count();

        auto ciph1_size = Anal1.w_c.save(Anal1.cipher1_stream); //print_parameters(*context);

        //cout << "\nKey Generation Time: " << diff1.count() << " milliseconds" << endl;
        parmsT = parmsT + diff1.count();
        auto ciph2_size = Anal1.b_c.save(Anal1.cipher2_stream);
        ciphT = ciphT + ciph1_size;

        // Decrypt the returned Ciphertext
        // cout << "Analyst decrypts the result" << endl;
        st3 = chrono::high_resolution_clock::now(); 
        vector<int64_t> decrypted_res = decrypting(Anal1.w_c, Anal1.he_sk, analyst_he_benc, *context, Anal1.w.size());
        end3 = chrono::high_resolution_clock::now(); 
        diff3 = chrono::duration_cast<chrono::milliseconds>(end3 - st3);         //Measure the time difference
        //print_vec(decrypted_res, decrypted_res.size(), "Decrypted Result");
        decT = decT + diff3.count();

    }

    //Compute the Average communication and computation
    cout << "[RES] Average Key Generation Time over " << AVG << " iterations: " << parmsT / AVG << " milliseconds" << endl;
    cout << "[RES] Average HE Encryption of Weights and Biases over " << AVG << " iterations: " << encT / AVG << " milliseconds" << endl;
    cout << "[RES] Average HE Decryption of C(res) over 50 iterations: " << decT / AVG << " milliseconds" << endl;
    cout << "[RES] Average Public Key size over " << AVG << " iterations: " << pkT / AVG << " bytes" << endl;
    cout << "[RES] Average Relin Key size over "<< AVG << " iterations: " << rkT / AVG << " bytes" << endl;
    cout << "[RES] Average Galois Key size over "<< AVG << " iterations: " << gkT / AVG << " bytes" << endl;
    cout << "[RES] Ciphertext size over "<< AVG << " iterations: " << ciphT / AVG << " bytes" << endl;



}
#include <vector>
#include <chrono>
#include <iostream>
#include <string>
#include <typeinfo>

#include "../../configs/config.h"
#include "../../src/SEAL_Cipher.h"
#include "../../src/pasta_3_plain.h"  // for PASTA_params
#include "../../src/pasta_3_seal.h"
#include "../../src/utils.h"
#include "../../src/sealhelper.h"

struct ServerData {
    Ciphertext w_c;  // the encrypted weights from the analyst
    Ciphertext b_c;  // the encrypted biases from the analyst
    vector<Ciphertext> c_res;  // the encrypted results
    vector<Ciphertext> c_prime;  // the encrypted data from the user
    PublicKey he_pk; // the he public key generated by the analyst
};

struct ExperimentResults {
    size_t avg_he_eval_time;
    size_t avg_he_result_data_memory;
};

int main() {
    print_example_banner("Performance and Communication Analysis for the Server in the 3-Party HE Setup");

    ServerData Server;
    ExperimentResults ExpRes;

    chrono::high_resolution_clock::time_point st0, end0;
    chrono::milliseconds t0;
    size_t total_he_eval_time = 0;
    size_t total_he_result_data_memory = 0;    

    // Create HE params
    shared_ptr<SEALContext> context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
    KeyGenerator keygen(*context);
    keygen.create_public_key(Server.he_pk);                                //HHE Encryption Key
    Evaluator server_he_eval(*context);
    BatchEncoder server_he_benc(*context);
    Encryptor server_he_enc(*context, Server.he_pk);
    Server.w_c = create_random_encrypted_vector(config::user_vector_size, Server.he_pk, server_he_benc, server_he_enc);
    Server.b_c = create_random_encrypted_vector(config::user_vector_size, Server.he_pk, server_he_benc, server_he_enc);
    
    // Doing evaluation on encrypted data, encrypted weights and biases
    for (int i = 0; i < config::NUM_RUN; i++) {
        Server.c_res.clear();
        size_t one_run_time = 0;
        size_t one_run_memory = 0;
        for (int j = 0; j < config::NUM_VEC; j++){
            Ciphertext x_c_j = create_random_encrypted_vector(config::user_vector_size, Server.he_pk, server_he_benc, server_he_enc);
            Ciphertext c_res_j;
            st0 = chrono::high_resolution_clock::now(); 
            packed_enc_multiply(x_c_j, Server.w_c, c_res_j, server_he_eval);
            packed_enc_addition(x_c_j, Server.b_c, c_res_j, server_he_eval);
            end0 = chrono::high_resolution_clock::now(); 
            t0 = chrono::duration_cast<chrono::milliseconds>(end0 - st0);
            Server.c_res.push_back(c_res_j);
            one_run_time += t0.count();
            stringstream cs;
            size_t size = c_res_j.save(cs);
            one_run_memory += size;
        }
        total_he_eval_time += one_run_time;
        total_he_result_data_memory += one_run_memory;
    }

    ExpRes.avg_he_eval_time = total_he_eval_time / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE eval time over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_he_eval_time << " ms" << endl;
    print_line(__LINE__);
    ExpRes.avg_he_result_data_memory = total_he_result_data_memory / config::NUM_RUN;
    cout << "--- RESULT: avg HE encrypted result memory over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_he_result_data_memory << " bytes" << endl;


    return 0;
}
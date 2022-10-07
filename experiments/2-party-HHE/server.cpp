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
    vector<int64_t> w{17, 31, 24, 17};  // dummy weights
    vector<int64_t> b{-5, -5, -5, -5};  // dummy biases
    Plaintext plain_w;
    Plaintext plain_b;
    vector<vector<uint64_t>> c_x; // the symmetric encrypted data from the user 
    vector<Ciphertext> c_k;  // the HE encrypted symmetric keys from the user
    vector<Ciphertext> c_prime; // the decomposed HE encrypted data
    vector<Ciphertext> c_res;  // the encrypted results
    PublicKey he_pk;  // the public key from the analyst
    SecretKey he_sk;
    RelinKeys he_rk;
    GaloisKeys he_gk;
};

struct ExperimentResults {
    size_t avg_he_eval_time;
    size_t avg_decomposition_time;
    size_t avg_computation_time;
    size_t avg_he_result_data_memory;
};

int main() {
    print_example_banner("Performance and Communication Analysis for the Server in the 2-Party HHE Setup");

    ServerData Server;
    ExperimentResults ExpRes;
    
    // Generate HE params
    shared_ptr<SEALContext> context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
    KeyGenerator keygen(*context);
    Server.he_sk = keygen.secret_key();                                    //HHE Decryption Secret Key
    keygen.create_public_key(Server.he_pk);                                //HHE Encryption Key
    keygen.create_relin_keys(Server.he_rk);                                //HHE RelinKey
    BatchEncoder server_he_benc(*context);
    Encryptor server_he_enc(*context, Server.he_pk);
    Evaluator server_he_eval(*context);
    vector<int> gk_indices = add_gk_indices(config::use_bsgs, server_he_benc);
    keygen.create_galois_keys(gk_indices, Server.he_gk);                   //HHE GaloisKey

    // encode the weights & biases
    server_he_benc.encode(Server.w, Server.plain_w);
    server_he_benc.encode(Server.b, Server.plain_b);

    // Get the HE encrypted symmetric keys from the user
    vector<uint64_t> user_ssk = get_symmetric_key();
    PASTA_3_MODIFIED_1::PASTA SymmetricEncryptor(user_ssk, config::plain_mod);
    Server.c_k = encrypt_symmetric_key(user_ssk, config::USE_BATCH, server_he_benc, server_he_enc);
    PASTA_3_MODIFIED_1::PASTA_SEAL CSPWorker(context, Server.he_pk, Server.he_sk, Server.he_rk, Server.he_gk);

    chrono::high_resolution_clock::time_point st1, st2, st3, end1, end2, end3;
    chrono::milliseconds diff1, diff2, diff3;
    size_t total_decomposition_time = 0;
    size_t total_he_eval_time = 0;
    size_t total_computation_time = 0;
    size_t total_he_result_data_memory = 0;

    // Doing evaluation on encrypted data, plaintext weights and biases
    for (int i = 0; i < config::NUM_RUN; i++) {
        Server.c_prime.clear();
        size_t one_run_decomp_time = 0;
        size_t one_run_eval_time = 0;
        size_t one_run_result_memory = 0;
        for (int j = 0; j < config::NUM_VEC; j++){
            vector<uint64_t> x_i = create_random_vector(config::user_vector_size);
            vector<uint64_t> c_i = SymmetricEncryptor.encrypt(x_i);
            // decomposition
            st1 = chrono::high_resolution_clock::now();                          //Start the timer
            vector<Ciphertext> c_prime_j  = CSPWorker.decomposition(x_i, Server.c_k, config::USE_BATCH);
            end1 = chrono::high_resolution_clock::now();                          //Start the timer
            Server.c_prime.push_back(c_prime_j[0]);
            diff1 = chrono::duration_cast<chrono::milliseconds>(end1 - st1); 
            one_run_decomp_time += diff1.count();
            // evaluation
            Ciphertext c_res_j;
            st2 = chrono::high_resolution_clock::now(); 
            packed_plain_multiply(c_prime_j[0], Server.plain_w, c_res_j, server_he_eval);
            packed_plain_addition(c_prime_j[0], Server.plain_b, c_res_j, server_he_eval);
            end2 = chrono::high_resolution_clock::now(); 
            diff2 = chrono::duration_cast<chrono::milliseconds>(end2 - st2);
            one_run_eval_time += diff2.count();
            // result memory
            stringstream cs;
            size_t size = c_res_j.save(cs);
            one_run_result_memory += size;
        }
        total_decomposition_time += one_run_decomp_time;
        total_he_eval_time += one_run_eval_time;
        total_computation_time += total_decomposition_time + total_he_eval_time;
        total_he_result_data_memory += one_run_result_memory;
    }

    ExpRes.avg_he_eval_time = total_he_eval_time / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE eval (plain & encrypted) time over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_he_eval_time << " ms" << endl;
    
    ExpRes.avg_decomposition_time = total_decomposition_time / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg decomposition time over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << 
            ExpRes.avg_decomposition_time << " ms" << endl;
    
    ExpRes.avg_computation_time = total_computation_time / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg computation time over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << 
            ExpRes.avg_computation_time << " ms" << endl;

    print_line(__LINE__);
    ExpRes.avg_he_result_data_memory = total_he_result_data_memory / config::NUM_RUN;
    cout << "--- RESULT: avg HE encrypted result memory over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_he_result_data_memory << " bytes" << endl;


    return 0;
}
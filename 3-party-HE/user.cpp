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
    vector<vector<int64_t>> x;  // plaintext data
    vector<Ciphertext> c_prime;  // HE encrypted data
    PublicKey he_pk;
    SecretKey he_sk;
    RelinKeys he_rk;
    GaloisKeys he_gk;
    Ciphertext c_res;
};

struct ExperimentResults {
    size_t avg_he_key_gen_time;
    size_t avg_he_key_memory;
    size_t avg_he_data_encryption_time;
    size_t avg_he_encrypted_data_memory;
    size_t avg_result_decryption_time;
};

int main() {
    print_example_banner("Performance and Communication Analysis for the User in the 3-Party HE Setup");

    UserData User;
    ExperimentResults ExpRes;
    
    chrono::high_resolution_clock::time_point st0, st1, st2, st3, end0, end1, end2, end3;
    chrono::milliseconds t0, t1, t2, t3;
    
    size_t total_he_key_gen_time = 0;
    size_t total_he_key_memory = 0;
    size_t total_he_data_encryption_time = 0;
    size_t total_he_encrypted_data_memory = 0;
    size_t total_result_decryption_time = 0;

    for (int i = 0; i < config::NUM_RUN; i++) {
        // Measure the HE keys generation time
        st0 = chrono::high_resolution_clock::now();  // Start the timer
        shared_ptr<SEALContext> context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
        size_t params_size = get_seal_params_size(config::plain_mod, config::mod_degree, config::seclevel);
        KeyGenerator keygen(*context);
        User.he_sk = keygen.secret_key();  // HHE Decryption Secret Key
        keygen.create_public_key(User.he_pk);  // HHE Encryption Key
        keygen.create_relin_keys(User.he_rk);  // HHE RelinKey
        BatchEncoder user_he_benc(*context);
        Encryptor user_he_enc(*context, User.he_pk);
        Evaluator user_he_eval(*context);
        vector<int> gk_indices = add_gk_indices(config::use_bsgs, user_he_benc);
        keygen.create_galois_keys(gk_indices, User.he_gk);
        end0 = chrono::high_resolution_clock::now();                          //End the timer
        t0 = chrono::duration_cast<chrono::milliseconds>(end0 - st0); // Measure the time difference 
        total_he_key_gen_time += t0.count();

        // Measure HE keys used memory
        stringstream pks, rks, gks;
        size_t pk_size = User.he_pk.save(pks);
        size_t rk_size = User.he_rk.save(rks);
        size_t gk_size = User.he_gk.save(gks);
        total_he_key_memory += rk_size + gk_size + params_size;

        // Encrypt the data using HE
        User.x.clear();
        User.c_prime.clear();
        size_t one_run_time = 0;
        size_t one_run_memory = 0;
        for (int j = 0; j < config::NUM_VEC; j++) {
            vector<int64_t> x_i = create_random_int_vector(config::user_vector_size);
            User.x.push_back(x_i);
            // print_vec(User.x[j], x_i.size(), "x_i");
            st1 = chrono::high_resolution_clock::now();  // Start the timer
            Ciphertext c_i = encrypting(x_i, User.he_pk, user_he_benc, user_he_enc);
            end1 = chrono::high_resolution_clock::now();  // End the timer
            t1 = chrono::duration_cast<chrono::milliseconds>(end1 - st1); // Measure the time difference 
            User.c_prime.push_back(c_i);
            one_run_time += t1.count();
            stringstream s;
            one_run_memory += c_i.save(s);
        }
        // cout << one_run_memory << endl;
        total_he_data_encryption_time += one_run_time;
        total_he_encrypted_data_memory += one_run_memory;
    }

    ExpRes.avg_he_key_gen_time = total_he_key_gen_time / config::NUM_RUN;
    ExpRes.avg_he_key_memory = total_he_key_memory / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE key generation time over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_he_key_gen_time << " ms" << endl;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE key memory calculated over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_he_key_memory << " bytes" << endl;

    ExpRes.avg_he_data_encryption_time = total_he_data_encryption_time / config::NUM_RUN;
    ExpRes.avg_he_encrypted_data_memory = total_he_encrypted_data_memory / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE data encryption time over " << config::NUM_RUN << 
            " runs when the user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_he_data_encryption_time << " ms" << endl;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE data memory calculated over " << config::NUM_RUN << 
            " runs when the user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_he_encrypted_data_memory << " bytes" << endl;

    return 0;
}
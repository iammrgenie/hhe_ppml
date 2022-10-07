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
};

struct AnalystData {
    PublicKey he_pk;
};

struct ExperimentResults {
    size_t avg_he_data_encryption_time;
    size_t avg_he_encrypted_data_memory;
};

int main() {
    print_example_banner("Performance and Communication Analysis for the User in the 3-Party HE Setup");

    UserData User;
    AnalystData Analyst;
    ExperimentResults ExpRes;
        
    shared_ptr<SEALContext> context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
    KeyGenerator keygen(*context);
    keygen.create_public_key(Analyst.he_pk);  // HHE Encryption Key
    BatchEncoder analyst_he_benc(*context);
    Encryptor analyst_he_enc(*context, Analyst.he_pk);
    Evaluator analyst_he_eval(*context);

    chrono::high_resolution_clock::time_point st1, end1;
    chrono::milliseconds t1;
    
    size_t total_he_data_encryption_time = 0;
    size_t total_he_encrypted_data_memory = 0;

    for (int i = 0; i < config::NUM_RUN; i++) {
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
            Ciphertext c_i = encrypting(x_i, Analyst.he_pk, analyst_he_benc, analyst_he_enc);
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
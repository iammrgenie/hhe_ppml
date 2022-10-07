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


struct UserData {
    vector<uint64_t> ssk;  // the secret symmetric keys
    std::vector<Ciphertext> c_k;  // the HE encrypted symmetric keys
    vector<vector<uint64_t>> x;  // plaintext data
    vector<vector<uint64_t>> c;  // symmetric encrypted data
};

struct AnalystData {
    PublicKey he_pk;
};

struct ExperimentResults {
    size_t avg_sym_enc_time;
    size_t avg_key_enc_time;
    size_t avg_encrypted_key_memory;
    size_t avg_symmetric_encrypted_data_memory;
};


int main() {
    print_example_banner("Performance and Communication Analysis for the User in the 3-Party HHE Setup");

    UserData User;
    AnalystData Analyst;
    ExperimentResults ExpRes;

    // print_vec(User.x_i, User.x_i.size(), "User.x_i");
    User.ssk = get_symmetric_key();
    
    // cout << "Analyst creates the HE parameters and HE context" << endl;
    shared_ptr<SEALContext> context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
    KeyGenerator keygen(*context);
    keygen.create_public_key(Analyst.he_pk);
    BatchEncoder analyst_he_benc(*context);
    Encryptor analyst_he_enc(*context, Analyst.he_pk);
    Evaluator analyst_he_eval(*context);

    // cout << "User encrypts his data using the symmetric key" << endl;
    PASTA_3_MODIFIED_1::PASTA SymmetricEncryptor(User.ssk, config::plain_mod);
    chrono::high_resolution_clock::time_point st1, st2, end1, end2;
    chrono::milliseconds t1, t2;
    size_t total_symmetric_enc_time = 0;
    size_t total_symmetric_enc_data_memory = 0;    
    size_t total_key_enc_time = 0;
    size_t total_encrypted_key_memory = 0;

    for (int i = 0; i < config::NUM_RUN; i++) {
        // Measuring symmetric data encryption time and memory  
        // After each run, clean the vectors User.x and User.c
        User.x.clear();
        User.c.clear();
        size_t one_run_time = 0;
        size_t one_run_memory = 0;
        for (int j = 0; j < config::NUM_VEC; j++) {
            vector<uint64_t> x_i = create_random_vector(4);
            User.x.push_back(x_i);
            // print_vec(User.x[j], x_i.size(), "x_i");
            st1 = chrono::high_resolution_clock::now();  // Start the timer
            vector<uint64_t> c_i = SymmetricEncryptor.encrypt(x_i);
            end1 = chrono::high_resolution_clock::now();  // End the timer
            t1 = chrono::duration_cast<chrono::milliseconds>(end1 - st1); //Measure the time difference 
            User.c.push_back(c_i);
            one_run_time += t1.count();
            one_run_memory += get_used_mem_usage(c_i);
        }
        total_symmetric_enc_time += one_run_time;
        total_symmetric_enc_data_memory += one_run_memory;

        // Measuring symmetric key encryption using HE
        st2 = chrono::high_resolution_clock::now();  // Start the timer
        User.c_k = encrypt_symmetric_key(User.ssk, config::USE_BATCH, analyst_he_benc, analyst_he_enc);
        end2 = chrono::high_resolution_clock::now();  // End the timer
        // User.c_k.save(s);
        t2 = chrono::duration_cast<chrono::milliseconds>(end2 - st2); //Measure the time difference 
        total_key_enc_time += t2.count();
        stringstream s;
        size_t size = (User.c_k[0]).save(s);
        total_encrypted_key_memory += size;
    }

    ExpRes.avg_sym_enc_time = total_symmetric_enc_time / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg symmetric encryption time over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_sym_enc_time << " ms" << endl;
    // print_vec(User.c_i, User.c_i.size(), "User.c_i"); 
    print_line(__LINE__);
    ExpRes.avg_symmetric_encrypted_data_memory = total_symmetric_enc_data_memory / config::NUM_RUN;
    cout << "--- RESULT: avg symmetric encrypted data memory over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_symmetric_encrypted_data_memory << " bytes" << endl;

    ExpRes.avg_key_enc_time = total_key_enc_time / config::NUM_RUN;
    ExpRes.avg_encrypted_key_memory = total_encrypted_key_memory / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg key encryption time over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_key_enc_time << " ms" << endl;
    print_line(__LINE__);
    cout << "--- RESULT: avg encrypted key size over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_encrypted_key_memory << " (bytes)" << endl;
    return 0;
}
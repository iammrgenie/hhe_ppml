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
    PublicKey he_pk;
    SecretKey he_sk;
    RelinKeys he_rk;
    GaloisKeys he_gk;
    Ciphertext c_res;  // the HE encrypted result
};

struct ExperimentResults {
    size_t avg_he_key_gen_time;
    size_t avg_he_key_memory;
    size_t avg_sym_enc_time;
    size_t avg_key_enc_time;
    size_t avg_encrypted_key_memory;
    size_t avg_symmetric_encrypted_data_memory;
    size_t avg_res_decryption_time;
};


int main() {
    print_example_banner("Performance and Communication Analysis for the User in the 2-Party HHE Setup");

    UserData User;
    ExperimentResults ExpRes;
    
    chrono::high_resolution_clock::time_point st0, st1, st2, st3, end0, end1, end2, end3;
    chrono::milliseconds t0, t1, t2, t3;
    
    size_t total_he_key_time = 0;
    size_t total_he_key_memory = 0;
    size_t total_sym_enc_time = 0;
    size_t total_encrypted_data_memory = 0;
    size_t total_key_enc_time = 0;
    size_t total_encrypted_key_memory = 0;
    size_t total_result_decryption_time = 0;

    for (int i = 0; i < config::NUM_RUN; i++) {
        // Measure HE keys generation time
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
        total_he_key_time += t0.count();
        
        // Measure HE keys used memory
        stringstream pks, rks, gks;
        size_t pk_size = User.he_pk.save(pks);
        size_t rk_size = User.he_rk.save(rks);
        size_t gk_size = User.he_gk.save(gks);
        total_he_key_memory += rk_size + gk_size + params_size;
        
        // Create the symmetric key
        User.ssk = get_symmetric_key();
        
        // Measure the symmetrically encryption of the data
        // cout << "User encrypts his data using the symmetric key" << endl;
        PASTA_3_MODIFIED_1::PASTA SymmetricEncryptor(User.ssk, config::plain_mod);
        // After each run, clean the vectors User.x and User.c
        User.x.clear();
        User.c.clear();
        size_t one_run_time = 0;
        size_t one_run_memory = 0;
        for (int j = 0; j < config::NUM_VEC; j++) {
            vector<uint64_t> x_i = create_random_vector(config::user_vector_size);
            User.x.push_back(x_i);
            // print_vec(User.x[j], x_i.size(), "x_i");
            st1 = chrono::high_resolution_clock::now();  // Start the timer
            vector<uint64_t> c_i = SymmetricEncryptor.encrypt(x_i);
            end1 = chrono::high_resolution_clock::now();  // End the timer
            t1 = chrono::duration_cast<chrono::milliseconds>(end1 - st1); // Measure the time difference 
            User.c.push_back(c_i);
            one_run_time += t1.count();
            one_run_memory += get_used_mem_usage(c_i);
        }
        // cout << one_run_memory << endl;
        total_sym_enc_time += one_run_time;
        total_encrypted_data_memory += one_run_memory;

        // Measure symmetric key encryption using HE
        st2 = chrono::high_resolution_clock::now();  // Start the timer
        User.c_k = encrypt_symmetric_key(User.ssk, config::USE_BATCH, user_he_benc, user_he_enc);
        end2 = chrono::high_resolution_clock::now();  // End the timer
        // User.c_k.save(s);
        t2 = chrono::duration_cast<chrono::milliseconds>(end2 - st2); //Measure the time difference 
        total_key_enc_time += t2.count();
        stringstream s;
        size_t size = (User.c_k[0]).save(s);
        total_encrypted_key_memory += size;
        
        // Decrypt the result got from the CSP
        User.c_res = create_random_encrypted_vector(config::user_vector_size, User.he_pk, user_he_benc, user_he_enc);
        st3 = chrono::high_resolution_clock::now(); 
        vector<int64_t> decrypted_res = decrypting(User.c_res, User.he_sk, user_he_benc, *context, config::user_vector_size);
        end3 = chrono::high_resolution_clock::now(); 
        t3 = chrono::duration_cast<chrono::milliseconds>(end3 - st3);         //Measure the time difference
        //print_vec(decrypted_res, decrypted_res.size(), "Decrypted Result");
        total_result_decryption_time += t3.count();
    }
    
    // Calculate avg measurements and print out results
    ExpRes.avg_he_key_gen_time = total_he_key_time / config::NUM_RUN;
    ExpRes.avg_he_key_memory = total_he_key_memory / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE key generation time over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_he_key_gen_time << " ms" << endl;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE key memory calculated over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_he_key_memory << " bytes" << endl;

    ExpRes.avg_sym_enc_time = total_sym_enc_time / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg symmetric encryption time over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_sym_enc_time << " ms" << endl;
    // print_vec(User.c_i, User.c_i.size(), "User.c_i"); 
    print_line(__LINE__);
    ExpRes.avg_symmetric_encrypted_data_memory = total_encrypted_data_memory / config::NUM_RUN;
    cout << "--- RESULT: avg symmetric encrypted data memory over " << config::NUM_RUN << 
            " runs when user has " << config::NUM_VEC << " vectors = " << ExpRes.avg_symmetric_encrypted_data_memory << " bytes" << endl;

    ExpRes.avg_key_enc_time = total_key_enc_time / config::NUM_RUN;
    ExpRes.avg_encrypted_key_memory = total_encrypted_key_memory / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg symmetric key encryption time using HE over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_key_enc_time << " ms" << endl;
    print_line(__LINE__);
    cout << "--- RESULT: avg encrypted key size over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_encrypted_key_memory << " bytes" << endl;

    ExpRes.avg_res_decryption_time = total_result_decryption_time / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg result decryption time over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_res_decryption_time << " ms" << endl;

    return 0;
}
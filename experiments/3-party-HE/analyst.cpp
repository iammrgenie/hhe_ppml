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

struct AnalystData {
    vector<int64_t> w{17, 31, 24, 17};  // dummy weights
    vector<int64_t> b{-5, -5, -5, -5};  // dummy biases
    Ciphertext w_c;  // the encrypted weights
    Ciphertext b_c;  // the encrypted biases
    PublicKey he_pk;
    SecretKey he_sk;
    RelinKeys he_rk;
    GaloisKeys he_gk;
    Ciphertext c_res;
};

struct ExperimentResults {
    size_t avg_he_key_gen_time;
    size_t avg_he_key_memory;
    size_t avg_he_wb_encryption_time;
    size_t avg_he_wb_data_memory;
    size_t avg_result_decryption_time;
};

int main() {
    print_example_banner("Performance and Communication Analysis for the Analyst in the 3-Party HE Setup");

    AnalystData Analyst;
    ExperimentResults ExpRes;

    chrono::high_resolution_clock::time_point st0, st1, st2, st3, end0, end1, end2, end3;
    chrono::milliseconds t0, t1, t2, t3;
    
    size_t total_he_key_gen_time = 0;
    size_t total_he_key_memory = 0;
    size_t total_he_wb_encryption_time = 0;  // time to encrypt weights and biases 
    size_t total_he_wb_data_memory = 0;  // weights and biases used memory
    size_t total_result_decryption_time = 0;

    for (int i = 0; i < config::NUM_RUN; i++) {
        // Measure the HE keys generation time
        st0 = chrono::high_resolution_clock::now();  // Start the timer
        shared_ptr<SEALContext> context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
        size_t params_size = get_seal_params_size(config::plain_mod, config::mod_degree, config::seclevel);
        KeyGenerator keygen(*context);
        Analyst.he_sk = keygen.secret_key();  // HHE Decryption Secret Key
        keygen.create_public_key(Analyst.he_pk);  // HHE Encryption Key
        keygen.create_relin_keys(Analyst.he_rk);  // HHE RelinKey
        BatchEncoder analyst_he_benc(*context);
        Encryptor analyst_he_enc(*context, Analyst.he_pk);
        Evaluator analyst_he_eval(*context);
        vector<int> gk_indices = add_gk_indices(config::use_bsgs, analyst_he_benc);
        keygen.create_galois_keys(gk_indices, Analyst.he_gk);
        end0 = chrono::high_resolution_clock::now();                          //End the timer
        t0 = chrono::duration_cast<chrono::milliseconds>(end0 - st0); // Measure the time difference 
        total_he_key_gen_time += t0.count();
        // Mesure the HE keys memory
        stringstream pks, rks, gks;
        size_t pk_size = Analyst.he_pk.save(pks);
        size_t rk_size = Analyst.he_rk.save(rks);
        size_t gk_size = Analyst.he_gk.save(gks);
        total_he_key_memory += rk_size + gk_size + params_size;

        // Encrypt weights and biases
        st1 = chrono::high_resolution_clock::now();                              //Start the timer
        Analyst.w_c = encrypting(Analyst.w, Analyst.he_pk, analyst_he_benc, analyst_he_enc);
        Analyst.b_c = encrypting(Analyst.b, Analyst.he_pk, analyst_he_benc, analyst_he_enc);
        end1 = chrono::high_resolution_clock::now();                             //End the timer
        t1 = chrono::duration_cast<chrono::milliseconds>(end1 - st1);         //Measure the time difference 
        total_he_wb_encryption_time += t1.count();
        // weights and biases memory
        stringstream ws, bs;
        auto size1 = Analyst.w_c.save(ws); //print_parameters(*context);
        auto size2 = Analyst.b_c.save(bs);
        total_he_wb_data_memory += size1 + size2;
        
        size_t one_run_decryption_time = 0;
        for (int j = 0; j < config::NUM_VEC; j++) {
			// Decrypt results
			Analyst.c_res = create_random_encrypted_vector(config::user_vector_size, Analyst.he_pk, analyst_he_benc, analyst_he_enc);
			st2 = chrono::high_resolution_clock::now(); 
			vector<int64_t> decrypted_res = decrypting(Analyst.c_res, Analyst.he_sk, analyst_he_benc, *context, config::user_vector_size);
			end2 = chrono::high_resolution_clock::now(); 
			t2 = chrono::duration_cast<chrono::milliseconds>(end2 - st2);         //Measure the time difference
			//print_vec(decrypted_res, decrypted_res.size(), "Decrypted Result");
			one_run_decryption_time += t2.count();
        }
		total_result_decryption_time += one_run_decryption_time;
    }

    ExpRes.avg_he_key_gen_time = total_he_key_gen_time / config::NUM_RUN;
    ExpRes.avg_he_key_memory = total_he_key_memory / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE key generation time over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_he_key_gen_time << " ms" << endl;
    print_line(__LINE__);
    cout << "--- RESULT: avg HE key memory calculated over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_he_key_memory << " bytes" << endl;

    ExpRes.avg_he_wb_encryption_time = total_he_wb_encryption_time / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg weights and biases HE encryption time over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_he_wb_encryption_time << " ms" << endl;

    ExpRes.avg_he_wb_data_memory = total_he_wb_data_memory / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg weights and biases HE data memory over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_he_wb_data_memory << " ms" << endl;

    ExpRes.avg_result_decryption_time = total_result_decryption_time / config::NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg result decryption time over " << config::NUM_RUN << 
            " runs = " << ExpRes.avg_result_decryption_time << " ms" << endl;

    return 0;
}
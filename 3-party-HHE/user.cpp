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

#define NUM_RUN 50 // number of runs to get the average measurements
#define NUM_VEC 10 // number of vectors the user have
static const bool USE_BATCH = true;

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
};

int main() {
    print_example_banner("Experiments: 3-party HHE User");

    UserData User;
    AnalystData Analyst;
    ExperimentResults ExpRes;

    // print_vec(User.x_i, User.x_i.size(), "User.x_i");
    User.ssk = get_symmetric_key();
    
    cout << "User encrypts his data using the symmetric key" << endl;
    uint64_t plain_mod = 65537;
    PASTA_3_MODIFIED_1::PASTA SymmetricEncryptor(User.ssk, plain_mod);
    chrono::high_resolution_clock::time_point st1, st2, end1, end2;
    chrono::milliseconds t1, t2;
    size_t total_time = 0;
    size_t total_memory = 0;
    // Measuring symmetric data encryption time and memory  
    for (int i = 0; i < NUM_RUN; i++) {
        // After each run, clean the vectors User.x and User.c
        User.x.clear();
        User.c.clear();
        size_t one_run_total_time = 0;
        size_t one_run_memory = 0;
        for (int j = 0; j < NUM_VEC; j++) {
            vector<uint64_t> x_i = create_random_vector(4);
            User.x.push_back(x_i);
            print_vec(User.x[j], x_i.size(), "x_i");
            st1 = chrono::high_resolution_clock::now();  // Start the timer
            vector<uint64_t> c_i = SymmetricEncryptor.encrypt(x_i);
            end1 = chrono::high_resolution_clock::now();  // End the timer
            t1 = chrono::duration_cast<chrono::milliseconds>(end1 - st1); //Measure the time difference 
            User.c.push_back(c_i);
            one_run_total_time += t1.count();
            cout <<   
        }
        total_time += one_run_total_time;
    }
    cout << "total symmetric encryption time over " << NUM_RUN << 
            " runs when user has " << NUM_VEC << " vectors = " << total_time << " ms" << endl;
    ExpRes.avg_sym_enc_time = total_time / NUM_RUN;
    print_line(__LINE__);
    cout << "--- RESULT: avg symmetric encryption time over " << NUM_RUN << 
            " runs when user has " << NUM_VEC << " vectors = " << ExpRes.avg_sym_enc_time << " ms" << endl;
    // print_vec(User.c_i, User.c_i.size(), "User.c_i"); 
    print_line(__LINE__);
    cout << "size of User.c " << sizeof(User.c) << endl;

    cout << "Analyst creates the HE parameters and HE context" << endl;
    uint64_t mod_degree = 16384;
    int seclevel = 128;
    shared_ptr<SEALContext> context = get_seal_context(plain_mod, mod_degree, seclevel);
    KeyGenerator keygen(*context);
    keygen.create_public_key(Analyst.he_pk);
    BatchEncoder analyst_he_benc(*context);
    Encryptor analyst_he_enc(*context, Analyst.he_pk);
    Evaluator analyst_he_eval(*context);

    // Measuring symmetric key encryption using HE
    cout << "User encrypts his symmetric key using the Analyst's HE configurations" << endl;
    size_t total_key_enc_time = 0;
    for (int i = 0; i < NUM_RUN; i++) {
        st2 = chrono::high_resolution_clock::now();  // Start the timer
        User.c_k = encrypt_symmetric_key(User.ssk, USE_BATCH, analyst_he_benc, analyst_he_enc);
        end2 = chrono::high_resolution_clock::now();  // End the timer
        // User.c_k.save(s);
        t2 = chrono::duration_cast<chrono::milliseconds>(end2 - st2); //Measure the time difference 
        total_key_enc_time += t2.count();
    }
    ExpRes.avg_key_enc_time = total_key_enc_time / NUM_RUN;
    cout << "--- RESULT: avg key encryption time over " << NUM_RUN << 
            " runs = " << ExpRes.avg_key_enc_time << " ms" << endl;

    return 0;
}
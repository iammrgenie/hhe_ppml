#include <vector>
#include <iostream>
#include <string>
#include <typeinfo>

#include "../pasta_modified_1/SEAL_Cipher.h"
#include "../pasta_modified_1/pasta_3_plain.h"  // for PASTA_params
#include "../pasta_modified_1/pasta_3_seal.h"
#include "../pasta_modified_1/utils.h"
#include "../pasta_modified_1/sealhelper.h"

#include "symmetric_encryption_test.cpp"

static const bool USE_BATCH = true;

using namespace std;
using namespace seal;

// Ciphertext encrypting(vector<int64_t> input, SEALContext context, PublicKey public_key) {
//     // encode and encrypt the input
//     BatchEncoder batch_encoder(context);
//     Encryptor encryptor(context, public_key);
//     Plaintext plain_input;
//     batch_encoder.encode(input, plain_input);
//     Ciphertext enc_input;
//     encryptor.encrypt(plain_input, enc_input);
//     return enc_input;
// }

// vector<int64_t> decrypting(Ciphertext enc_input, SEALContext context, SecretKey secret_key) {
//     // decrypt and decode the encrypted input
//     BatchEncoder batch_encoder(context);
//     Decryptor decryptor(context, secret_key);
//     Plaintext plain_input;
//     decryptor.decrypt(enc_input, plain_input);
//     vector<int64_t> vec_input;
//     batch_encoder.decode(plain_input, vec_input);
//     return vec_input;
// }

struct UserData {
    vector<uint64_t> symmetric_key;  // the symmetric keys
    vector<uint64_t> x_i{0, 1, 2, 3};
    vector<uint64_t> c_i;  // symmetric encrypted x_i
    std::vector<Ciphertext> c_k;  // the HE encrypted symmetric keys
};

struct AnalystData {  
    vector<int64_t> w{17, 31, 24, 17};  // dummy weights
    vector<int64_t> b{-5, -5, -5, -5};  // dummy biases
    Ciphertext w_c;  // the encrypted weights
    Ciphertext b_c;  // the encrypted biases
};

struct CSPData {
    std::vector<Ciphertext> c_prime;  // the decomposed HE encrypted data of user's c_i
    Ciphertext c_res;  // the HE encrypted results that will be sent to the Analyst
};

int main() {
    print_example_banner("Testing the HHE protocol with 1 party using the PASTA library");

    // The parties in the protocol
    UserData User;
    AnalystData Analyst;
    CSPData CSP;

    print_line(__LINE__);
    cout << "---- Analyst ----" << endl;
    cout << "Analyst creates the HE parameters and HE context" << endl;
    uint64_t plain_mod = 65537;
    uint64_t mod_degree = 16384;
    int seclevel = 128;
    shared_ptr<SEALContext> context = get_seal_context(plain_mod, mod_degree, seclevel);
    print_parameters(*context);
    print_line(__LINE__);
    cout << "Analyst creates the keys from the context" << endl;
    KeyGenerator keygen(*context);
    SecretKey he_sk = keygen.secret_key();  // HE Decryption Secret Key
    PublicKey he_pk;  // HE Encryption Public Key
    keygen.create_public_key(he_pk);
    print_line(__LINE__);
    cout << "Analyst creates the batch encoder and encryptor from the context and keys" << endl;
    BatchEncoder he_benc(*context);
    Encryptor he_enc(*context, he_pk);

    cout << endl;
    print_line(__LINE__);
    cout << "---- User ----" << endl;
    // Get the random Symmetric Key
    cout << "User creates the symmetric key" << endl;
    User.symmetric_key = get_symmetric_key();
    print_line(__LINE__);
    // print_vec(User.symmetric_key, User.symmetric_key.size(), "sk");
    cout << "User encrypts his data using the symmetric key" << endl;
    print_vec(User.x_i, User.x_i.size(), "User.x_i");
    PASTA_3_MODIFIED_1::PASTA SymmetricEncryptor(User.symmetric_key, plain_mod);
    User.c_i = SymmetricEncryptor.encrypt(User.x_i);
    print_vec(User.c_i, User.c_i.size(), "User.c_i");
    TEST::symmetric_data_encryption_test(User.x_i, User.c_i, SymmetricEncryptor);
    print_line(__LINE__);
    cout << "User encrypts his symmetric key using HE" << endl;
    auto enc_ssk = encrypt_symmetric_key(User.symmetric_key, USE_BATCH, he_benc, he_enc);
    TEST::symmetric_key_he_encryption_test(User.symmetric_key, USE_BATCH, context, he_sk, he_pk, he_benc, he_enc);
    // PASTA_3_MODIFIED_1::PASTA_SEAL M1(context, he_sk, he_pk);

    // PASTA_3_MODIFIED_1::PASTA_SEAL CSP(in_key, context);
    // //Initiate the Class for Encryforwardption and Decryption using PASTA Symmetric Key for Encryption and Decryption

    // //Print the necessary parameters to screen
    // M1.print_parameters();

    // //compute the HE encryption of the secret key and measure performance
    // // M1.activate_bsgs(false);
    // M1.add_gk_indices();
    // M1.create_gk();

    // //Encrypt the secret key with HE
    // cout << "\nUsing HE to encrypt the user's symmetric key ..." << flush;
    // M1.encrypt_key(USE_BATCH);
    // cout << endl;
    // cout << "Checking: decrypting the HE encrypted key" << endl;
    // vector<uint64_t> dec_sym_key;
    // auto M1_sk = M1.get_enc_sk();
    // cout << "M1_sk size = " << M1_sk.size() << endl;
    // dec_sym_key = M1.decrypt_result(M1_sk, USE_BATCH);
    // cout << "symmetric key size = " << in_key.size() << "; decrypted key size = " << dec_sym_key.size() << endl;

    // auto enc_key2 = M1.encrypt_key_2(in_key, USE_BATCH);
    // vector<uint64_t> dec_sym_key2;
    // dec_sym_key2 = M1.decrypt_result(enc_key2, USE_BATCH);
    // // print_vec(in_key, in_key.size(), "symmetric key");
    // print_vec(dec_sym_key, dec_sym_key.size(), "dec_sym_key");
    // print_vec(dec_sym_key2, dec_sym_key2.size(), "dec_sym_key");
    // if (dec_sym_key != dec_sym_key2) throw runtime_error("decypted keys are different");

    // // Set dummy plaintext and test encryption and decryption
    // cout << "\nPlaintext user input: " << endl;
    // print_vec(Test.x_i, Test.x_i.size(), "x_i");
     
    // //Encrypt plaintext with the symmetric secret key
    // cout << "\nSymmetrically encrypt the user input ..." << endl;
    // Test.c_i = EN.encrypt(Test.x_i);
    // print_vec(Test.c_i, Test.c_i.size(), "c_i");

    // //Encrypt the analyst's weights and biases
    // cout << "\nAnalyst's weights and biases in plaintext: " << endl;
    // print_vec(Analyst.w, Analyst.w.size(), "w");
    // print_vec(Analyst.b, Analyst.b.size(), "b");
    // cout << "Encrypting the analyst's weights and biases..." << endl;
    // // Analyst.w_c = encrypting(Analyst.w, seal_context, M1.get_he_pk());
    // // Analyst.b_c = encrypting(Analyst.b, seal_context, M1.get_he_pk());
    // M1.packed_encrypt(Analyst.w_c, Analyst.w);
    // M1.packed_encrypt(Analyst.b_c, Analyst.b);
    // cout << "Checking: Analyst decrypts his weights and biases" << endl;
    // vector<int64_t> w_d, b_d;
    // // w_d = decrypting(Analyst.w_c, *context, M1.get_he_sk());
    // // b_d = decrypting(Analyst.b_c, *context, M1.get_he_sk());
    // M1.packed_decrypt(Analyst.w_c, w_d, Analyst.w.size());
    // M1.packed_decrypt(Analyst.b_c, b_d, Analyst.b.size());
    // print_vec(w_d, w_d.size(), "w_d");
    // print_vec(b_d, b_d.size(), "b_d");

    // //HHE Decomposition using the Symmetric Ciphertext and the HE encrypted key
    // cout << "\nDecomposing: turn symmetric encrypted data into he encrypted data ...\n" << flush;
    // // Test.c_1 = M1.HE_decrypt(Test.c_i, USE_BATCH);
    // Test.c_1 = M1.HE_decrypt_2(Test.c_i, enc_key2, USE_BATCH);
    // Ciphertext c_prime = Test.c_1[0];

    // //HE Evaluation of the encrypted linear transformation
    // cout << "\nEvaluating an encrypted linear transformation: c' * w_c + b_c .... \n" << flush;
    // // Evaluator seal_evaluator(seal_context);
    // Ciphertext c_res;
    // M1.packed_enc_mul(Analyst.w_c, c_prime, c_res);
    // M1.packed_enc_add(Analyst.b_c, c_res, c_res);

    // cout << "\nAnalyst decrypt the result" << endl;
    // // vector<int64_t> res = decrypting(c_res, seal_context, M1.get_he_sk());
    // vector<int64_t> res;
    // M1.packed_decrypt(c_res, res, Analyst.w.size());
    // print_vec(res, res.size(), "res");
    
    return 0;
}
#include <vector>
#include <iostream>
#include <string>
#include <typeinfo>

#include "../configs/config.h"
#include "../src/SEAL_Cipher.h"
#include "../src/pasta_3_plain.h" // for PASTA_params
#include "../src/pasta_3_seal.h"
#include "../src/utils.h"
#include "../src/sealhelper.h"
#include "../tests/symmetric_encryption_test.cpp"
#include "../tests/he_test.cpp"

using namespace std;
using namespace seal;

struct UserData
{
    vector<uint64_t> ssk; // the secret symmetric keys
    vector<uint64_t> x_i{0, 1, 2, 3};
    vector<uint64_t> c_i;        // symmetric encrypted x_i
    std::vector<Ciphertext> c_k; // the HE encrypted symmetric keys
};

struct AnalystData
{
    vector<int64_t> w{17, 31, 24, 17}; // dummy weights
    vector<int64_t> b{-5, -5, -5, -5}; // dummy biases
    Ciphertext w_c;                    // the encrypted weights
    Ciphertext b_c;                    // the encrypted biases
    PublicKey he_pk;
    SecretKey he_sk;
    RelinKeys he_rk;
    GaloisKeys he_gk;
};

struct CSPData
{
    std::vector<Ciphertext> c_prime; // the decomposed HE encrypted data of user's c_i
    Ciphertext c_res;                // the HE encrypted results that will be sent to the Analyst
    SecretKey he_sk;
};

int main()
{
    print_example_banner("Testing the HHE protocol with 1 party using the PASTA library");

    // The parties in the protocol
    UserData User;
    AnalystData Analyst;
    CSPData CSP;

    cout << endl;
    print_line(__LINE__);
    cout << "---- Analyst ----" << endl;
    cout << "Analyst creates the HE parameters and HE context" << endl;
    shared_ptr<SEALContext> context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
    print_parameters(*context);
    print_line(__LINE__);
    cout << "Analyst creates the HE keys, batch encoder, encryptor and evaluator from the context" << endl;
    KeyGenerator keygen(*context);
    Analyst.he_sk = keygen.secret_key(); // HE Decryption Secret Key
    keygen.create_public_key(Analyst.he_pk);
    keygen.create_relin_keys(Analyst.he_rk);
    BatchEncoder analyst_he_benc(*context);
    Encryptor analyst_he_enc(*context, Analyst.he_pk);
    Evaluator analyst_he_eval(*context);
    bool use_bsgs = false;
    vector<int> gk_indices = add_gk_indices(use_bsgs, analyst_he_benc);
    keygen.create_galois_keys(gk_indices, Analyst.he_gk);
    print_line(__LINE__);
    // Decryptor analyst_he_dec(*context, Analyst.he_sk);
    print_line(__LINE__);
    cout << "Analyst encrypts his weights and biases" << endl;
    print_vec(Analyst.w, Analyst.w.size(), "Analyst.w");
    print_vec(Analyst.b, Analyst.b.size(), "Analyst.b");
    Analyst.w_c = encrypting(Analyst.w, Analyst.he_pk, analyst_he_benc, analyst_he_enc);
    Analyst.b_c = encrypting(Analyst.b, Analyst.he_pk, analyst_he_benc, analyst_he_enc);
    vector<int64_t> w_d = decrypting(Analyst.w_c, Analyst.he_sk, analyst_he_benc, *context, Analyst.w.size());
    vector<int64_t> b_d = decrypting(Analyst.b_c, Analyst.he_sk, analyst_he_benc, *context, Analyst.b.size());
    print_line(__LINE__);
    cout << "Aanalyst decrypts weights and biases to check" << endl;
    TEST::he_enc_dec_test(Analyst.w, w_d);
    TEST::he_enc_dec_test(Analyst.b, b_d);

    cout << endl;
    print_line(__LINE__);
    cout << "---- User ----" << endl;
    cout << "User creates the symmetric key" << endl;
    User.ssk = get_symmetric_key();
    // cout << "User.ssk.size() = " << User.ssk.size() << endl;
    // print_vec(User.ssk, User.ssk.size(), "sk");
    print_vec(User.x_i, User.x_i.size(), "User.x_i");
    print_line(__LINE__);
    cout << "User encrypts his data using the symmetric key" << endl;
    PASTA_3_MODIFIED_1::PASTA SymmetricEncryptor(User.ssk, config::plain_mod);
    User.c_i = SymmetricEncryptor.encrypt(User.x_i);
    print_vec(User.c_i, User.c_i.size(), "User.c_i");
    TEST::symmetric_data_encryption_test(User.x_i, User.c_i, SymmetricEncryptor);
    print_line(__LINE__);
    cout << "User encrypts his symmetric key using the Analyst's HE configurations" << endl;
    User.c_k = encrypt_symmetric_key(User.ssk, config::USE_BATCH, analyst_he_benc, analyst_he_enc);
    // cout << "User.c_k.size() = " << User.c_k.size() << endl;
    TEST::symmetric_key_he_encryption_test(User.c_k, User.ssk, config::USE_BATCH, context,
                                           Analyst.he_sk, Analyst.he_pk, Analyst.he_rk, Analyst.he_gk,
                                           analyst_he_benc, analyst_he_enc);

    cout << endl;
    print_line(__LINE__);
    cout << "---- CSP ----" << endl;
    print_line(__LINE__);
    cout << "CSP creates a new HE secret key from the context" << endl;
    KeyGenerator csp_keygen(*context);
    CSP.he_sk = csp_keygen.secret_key();
    TEST::he_sk_test(Analyst.he_sk, CSP.he_sk); // throw an error if 2 keys are the same
    print_line(__LINE__);
    cout << "Making a PASTA_SEAL Worker Object for the CSP based on the new CSP HE sk and the Analyst's HE pk" << endl;
    PASTA_3_MODIFIED_1::PASTA_SEAL CSPWorker(context, Analyst.he_pk, CSP.he_sk, Analyst.he_rk, Analyst.he_gk);
    print_line(__LINE__);
    cout << "CSP Decompose: Turning the user's SKE encrypted data c_i into HE encryped c_prime" << endl;
    CSP.c_prime = CSPWorker.decomposition(User.c_i, User.c_k, config::USE_BATCH);
    cout << "CSP.c_prime.size = " << CSP.c_prime.size() << endl;
    // cout << "CSP.prime[0].size = " << CSP.c_prime[0].size() << endl;
    // for debugging
    // vector<int64_t> dec_c_prime = decrypting(CSP.c_prime[0], Analyst.he_sk, analyst_he_benc, *context, Analyst.w.size());
    // print_vec(dec_c_prime, dec_c_prime.size(), "decrypted c_prime");
    print_line(__LINE__);
    cout << "CSP Evaluate a linear transformation using c_prime, Analyst's encrypted weights and biases" << endl;
    packed_enc_multiply(CSP.c_prime[0], Analyst.w_c, CSP.c_res, analyst_he_eval);
    packed_enc_addition(CSP.c_res, Analyst.b_c, CSP.c_res, analyst_he_eval);

    cout << endl;
    print_line(__LINE__);
    cout << "---- Analyst ----" << endl;
    cout << "Analyst decrypts the result" << endl;
    vector<int64_t> decrypted_res = decrypting(CSP.c_res, Analyst.he_sk, analyst_he_benc, *context, Analyst.w.size());
    print_vec(decrypted_res, decrypted_res.size(), "decrypted result");

    return 0;
}
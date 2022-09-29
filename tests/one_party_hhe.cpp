#include <vector>
#include <iostream>
#include <string>
#include <typeinfo>

#include "../pasta_modified_1/SEAL_Cipher.h"
//#include "HHE/ciphers/common/utils.h"
#include "../pasta_modified_1/pasta_3_plain.h"  // for PASTA_params

#include "../pasta_modified_1/pasta_3_seal.h"
#include "../sealhelper.h"

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
    vector<uint64_t> x_i{0, 1, 2, 3};
    vector<uint64_t> c_i;
    vector<seal::Ciphertext> c_1;
    vector<seal::Ciphertext> c_2;
    vector<uint64_t> x_p;
};

struct AnalystData {  
    vector<int64_t> w{17, 31, 24, 17};  // dummy weights for now
    vector<int64_t> b{-5, -5, -5, -5};  // dummy biases for now
    Ciphertext w_c; // Ciphertext or 
    Ciphertext b_c;
};

int main() {
    print_example_banner("Testing the HHE protocol with 1 party using the PASTA library");

    //int cnt = 2;
    UserData Test;
    AnalystData Analyst;
    
    //Random Symmetric Key
    vector<uint64_t> in_key = {0x07a30, 0x0cfe2, 0x03bbb, 0x06ab7, 0x0de0b, 0x0c36c, 0x01c39, 0x019e0,
                                      0x0e09c, 0x04441, 0x0c560, 0x00fd4, 0x0c611, 0x0a3fd, 0x0d408, 0x01b17,
                                      0x0fa02, 0x054ea, 0x0afeb, 0x0193b, 0x0b6fa, 0x09e80, 0x0e253, 0x03f49,
                                      0x0c8a5, 0x0c6a4, 0x0badf, 0x0bcfc, 0x0ecbd, 0x06ccd, 0x04f10, 0x0f1d6,
                                      0x07da9, 0x079bd, 0x08e84, 0x0b774, 0x07435, 0x09206, 0x086d4, 0x070d4,
                                      0x04383, 0x05d65, 0x0b015, 0x058fe, 0x0f0d1, 0x0c700, 0x0dc40, 0x02cea,
                                      0x096db, 0x06c84, 0x008ef, 0x02abc, 0x03fdf, 0x0ddaf, 0x028c7, 0x0ded4,
                                      0x0bb88, 0x020cd, 0x075c3, 0x0caf7, 0x0a8ff, 0x0eadd, 0x01c02, 0x083b1,
                                      0x0a439, 0x0e2db, 0x09baa, 0x02c09, 0x0b5ba, 0x0c7f5, 0x0161c, 0x0e94d,
                                      0x0bf6f, 0x070f1, 0x0f574, 0x0784b, 0x08cdb, 0x08529, 0x027c9, 0x010bc,
                                      0x079ca, 0x01ff1, 0x0219a, 0x00130, 0x0ff77, 0x012fb, 0x03ca6, 0x0d27d,
                                      0x05747, 0x0fa91, 0x00766, 0x04f27, 0x00254, 0x06e8d, 0x0e071, 0x0804e,
                                      0x08b0e, 0x08e59, 0x04cd8, 0x0485f, 0x0bde0, 0x03082, 0x01225, 0x01b5f,
                                      0x0a83e, 0x0794a, 0x05104, 0x09c19, 0x0fdcf, 0x036fe, 0x01e41, 0x00038,
                                      0x086e8, 0x07046, 0x02c07, 0x04953, 0x07869, 0x0e9c1, 0x0af86, 0x0503a,
                                      0x00f31, 0x0535c, 0x0c2cb, 0x073b9, 0x028e3, 0x03c2b, 0x0cb90, 0x00c33,
                                      0x08fe7, 0x068d3, 0x09a8c, 0x008e0, 0x09fe8, 0x0f107, 0x038ec, 0x0b014,
                                      0x007eb, 0x06335, 0x0afcc, 0x0d55c, 0x0a816, 0x0fa07, 0x05864, 0x0dc8f,
                                      0x07720, 0x0deef, 0x095db, 0x07cbe, 0x0834e, 0x09adc, 0x0bab8, 0x0f8f7,
                                      0x0b21a, 0x0ca98, 0x01a6c, 0x07e4a, 0x04545, 0x078a7, 0x0ba53, 0x00040,
                                      0x09bc5, 0x0bc7a, 0x0401c, 0x00c30, 0x00000, 0x0318d, 0x02e95, 0x065ed,
                                      0x03749, 0x090b3, 0x01e23, 0x0be04, 0x0b612, 0x08c0c, 0x06ea3, 0x08489,
                                      0x0a52c, 0x0aded, 0x0fd13, 0x0bd31, 0x0c225, 0x032f5, 0x06aac, 0x0a504,
                                      0x0d07e, 0x0bb32, 0x08174, 0x0bd8b, 0x03454, 0x04075, 0x06803, 0x03df5,
                                      0x091a0, 0x0d481, 0x09f04, 0x05c54, 0x0d54f, 0x00344, 0x09ffc, 0x00262,
                                      0x01fbf, 0x0461c, 0x01985, 0x05896, 0x0fedf, 0x097ce, 0x0b38d, 0x0492f,
                                      0x03764, 0x041ad, 0x02849, 0x0f927, 0x09268, 0x0bafd, 0x05727, 0x033bc,
                                      0x03249, 0x08921, 0x022da, 0x0b2dc, 0x0e42d, 0x055fa, 0x0a654, 0x073f0,
                                      0x08df1, 0x08149, 0x00d1b, 0x0ac47, 0x0f304, 0x03634, 0x0168b, 0x00c59,
                                      0x09f7d, 0x0596c, 0x0d164, 0x0dc49, 0x038ff, 0x0a495, 0x07d5a, 0x02d4,
                                      0x06c6c, 0x0ea76, 0x09af5, 0x0bea6, 0x08eea, 0x0fbb6, 0x09e45, 0x0e9db,
                                      0x0d106, 0x0e7fd, 0x04ddf, 0x08bb8, 0x0a3a4, 0x03bcd, 0x036d9, 0x05acf
    };

    //Set the Homorphic Parameters
  	uint64_t plain_mod = 65537;
  	uint64_t mod_degree = 16384;
  	int seclevel = 128;

    if (seclevel != 128) throw runtime_error("Security Level not supported");
    seal::sec_level_type sec = seal::sec_level_type::tc128;

    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(mod_degree);

    if (mod_degree == 65536) {
        sec = seal::sec_level_type::none;
        parms.set_coeff_modulus(
            {0xffffffffffc0001, 0xfffffffff840001, 0xfffffffff6a0001,
             0xfffffffff5a0001, 0xfffffffff2a0001, 0xfffffffff240001,
             0xffffffffefe0001, 0xffffffffeca0001, 0xffffffffe9e0001,
             0xffffffffe7c0001, 0xffffffffe740001, 0xffffffffe520001,
             0xffffffffe4c0001, 0xffffffffe440001, 0xffffffffe400001,
             0xffffffffdda0001, 0xffffffffdd20001, 0xffffffffdbc0001,
             0xffffffffdb60001, 0xffffffffd8a0001, 0xffffffffd840001,
             0xffffffffd6e0001, 0xffffffffd680001, 0xffffffffd2a0001,
             0xffffffffd000001, 0xffffffffcf00001, 0xffffffffcea0001,
             0xffffffffcdc0001, 0xffffffffcc40001});  // 1740 bits
    } else {
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(mod_degree));
    }
    parms.set_plain_modulus(plain_mod);
    // SEALContext seal_context(parms);
    auto context = make_shared<seal::SEALContext>(parms, true, sec);

    PASTA_3_MODIFIED_1::PASTA_SEAL M1(in_key, context);
    //Initiate the Class for Encryption and Decryption using PASTA Symmetric Key for Encryption and Decryption
    PASTA_3_MODIFIED_1::PASTA EN(in_key, plain_mod);

    //Print the necessary parameters to screen
    M1.print_parameters();

    //compute the HE encryption of the secret key and measure performance
    M1.activate_bsgs(false);
    M1.add_gk_indices();
    M1.create_gk();

    //Encrypt the secret key with HE
    cout << "\nUsing HE to encrypt the user's symmetric key ..." << flush;
    M1.encrypt_key(USE_BATCH);
    cout << endl;
    cout << "Checking: decrypting the HE encrypted key" << endl;
    vector<uint64_t> dec_sym_key;
    auto M1_sk = M1.get_sk();
    cout << "M1_sk size = " << M1_sk.size() << endl;
    dec_sym_key = M1.decrypt_result(M1_sk, USE_BATCH);
    cout << "symmetric key size = " << in_key.size() << "; decrypted key size = " << dec_sym_key.size() << endl;
    // print_vec(in_key, in_key.size(), "symmetric key");
    // print_vec(dec_sym_key, dec_sym_key.size(), "dec_sym_key");

    //Set dummy plaintext and test encryption and decryption
    cout << "\nPlaintext user input: " << endl;
    print_vec(Test.x_i, Test.x_i.size(), "x_i");
     
    //Encrypt plaintext with the symmetric secret key
    cout << "\nSymmetrically encrypt the user input ..." << endl;
    Test.c_i = EN.encrypt(Test.x_i);
    print_vec(Test.c_i, Test.c_i.size(), "c_i");

    //Encrypt the analyst's weights and biases
    cout << "\nAnalyst's weights and biases in plaintext: " << endl;
    print_vec(Analyst.w, Analyst.w.size(), "w");
    print_vec(Analyst.b, Analyst.b.size(), "b");
    cout << "Encrypting the analyst's weights and biases..." << endl;
    // Analyst.w_c = encrypting(Analyst.w, seal_context, M1.get_he_pk());
    // Analyst.b_c = encrypting(Analyst.b, seal_context, M1.get_he_pk());
    M1.packed_encrypt(Analyst.w_c, Analyst.w);
    M1.packed_encrypt(Analyst.b_c, Analyst.b);
    cout << "Checking: Analyst decrypts his weights and biases" << endl;
    vector<int64_t> w_d, b_d;
    // w_d = decrypting(Analyst.w_c, *context, M1.get_he_sk());
    // b_d = decrypting(Analyst.b_c, *context, M1.get_he_sk());
    M1.packed_decrypt(Analyst.w_c, w_d, Analyst.w.size());
    M1.packed_decrypt(Analyst.b_c, b_d, Analyst.b.size());
    print_vec(w_d, w_d.size(), "w_d");
    print_vec(b_d, b_d.size(), "b_d");

    //HHE Decomposition using the Symmetric Ciphertext and the HE encrypted key
    cout << "\nDecomposing: turn symmetric encrypted data into he encrypted data ...\n" << flush;
    Test.c_1 = M1.HE_decrypt(Test.c_i, USE_BATCH);
    Ciphertext c_prime = Test.c_1[0];

    //HE Evaluation of the encrypted linear transformation
    cout << "\nEvaluating an encrypted linear transformation: c' * w_c + b_c .... \n" << flush;
    // Evaluator seal_evaluator(seal_context);
    Ciphertext c_res;
    M1.packed_enc_mul(Analyst.w_c, c_prime, c_res);
    M1.packed_enc_add(Analyst.b_c, c_res, c_res);

    cout << "\nAnalyst decrypt the result" << endl;
    // vector<int64_t> res = decrypting(c_res, seal_context, M1.get_he_sk());
    vector<int64_t> res;
    M1.packed_decrypt(c_res, res, Analyst.w.size());
    print_vec(res, res.size(), "res");
    
    return 0;
}
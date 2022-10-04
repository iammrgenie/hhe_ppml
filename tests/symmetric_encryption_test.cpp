// #include "../pasta_modified_1/pasta_3_plain.h"
#include "../pasta_modified_1/pasta_3_seal.h"
#include "../pasta_modified_1/sealhelper.h"
// #include "../pasta_modified_1/utils.h"

using namespace std;
using namespace seal;

namespace TEST {

// decrypt c_i to see if it is equals to x_i
void symmetric_data_encryption_test(vector<uint64_t> x_i, 
                                    vector<uint64_t> c_i, 
                                    const PASTA_3_MODIFIED_1::PASTA &encryptor)
{
    auto c_i_dec = encryptor.decrypt(c_i);
    // print_vec(c_i_dec, c_i_dec.size(), "decrypted c_i");
    if (c_i_dec != x_i) throw runtime_error("decypted vector is different than the plaintext vector");
    cout << "TEST: symmetric data encryption test passed!" << endl;
} 

// encrypt the symmetric key using HE with the customized version and the PASTA version, 
// then check the results to see if they are the same 
void symmetric_key_he_encryption_test(vector<Ciphertext> enc_ssk,
                                      vector<uint64_t> ssk,
                                      bool USE_BATCH, 
                                      shared_ptr<SEALContext> context,
                                      const SecretKey &sk,
                                      const PublicKey &pk,
                                      const RelinKeys &rk,
                                      const GaloisKeys &gk,
                                      const BatchEncoder &he_benc,
                                      const Encryptor &he_enc)
{
    PASTA_3_MODIFIED_1::PASTA_SEAL M1(context, pk, sk, rk, gk);
    auto enc_ssk_pasta = M1.encrypt_key_2(ssk, USE_BATCH);
    // vector<Ciphertext> enc_ssk = encrypt_symmetric_key(ssk, USE_BATCH, he_benc, he_enc);
    vector<uint64_t> dec_ssk_pasta = M1.decrypt_result(enc_ssk_pasta, USE_BATCH);
    vector<uint64_t> dec_ssk = M1.decrypt_result(enc_ssk, USE_BATCH);
    // print_vec(dec_ssk_pasta, dec_ssk_pasta.size(), "dec_ssk_pasta");
    // print_vec(dec_ssk, dec_ssk.size(), "dec_ssk");
    if (dec_ssk != dec_ssk_pasta) throw runtime_error("decrypted symmetric keys are different");
    cout << "TEST: symmetric key encryption using HE test passed!" << endl;
}

}  // namespace TEST
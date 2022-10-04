#include "../pasta_modified_1/utils.h"

using namespace std;
using namespace seal;

namespace TEST {

// compare if 2 secret keys are the same by checking their addresses
void he_sk_test(SecretKey sk1, SecretKey sk2) {
    if (&sk1 == &sk2) throw runtime_error("2 secret keys are the same");
    cout << "TEST: HE secret keys test passed!" << endl;
}

// compare if the HE decrypted and plaintext data are the same
void he_enc_dec_test(const vector<int64_t> &plaintext , const vector<int64_t> &decryptedtext) {
    if (plaintext != decryptedtext) throw runtime_error("plain and decrypted data are different");
    cout << "TEST: HE encryption and decryption test passed!" << endl;
}

} // namespace TEST
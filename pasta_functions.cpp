#include <seal/seal.h>
#include <iostream>

#include "pasta_3_seal.h"
#include "Cipher.h"

using namespace std;
using namespace seal;


vector<Ciphertext> encrypt_key(bool batch_encoder, Encryptor E, BatchEncoder B, vector<uint64_t> in_key) {
    vector<Ciphertext> outcipher;
    
    (void)batch_encoder;  // patched implementation: ignore param
    outcipher.resize(1);
    
    Plaintext k;
    vector<uint64_t> key_tmp(halfslots + PASTA_T, 0);
    
    for (size_t i = 0; i < PASTA_T; i++) {
        key_tmp[i] = in_key[i];
        key_tmp[i + halfslots] = in_key[i + PASTA_T];
    }
    
    B.encode(key_tmp, k);
    E.encrypt(k, outcipher[0]);

    return outcipher;
}
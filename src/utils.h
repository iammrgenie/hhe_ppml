#ifndef UTIL_H
#define UTIL_H

#include <vector>
#include <algorithm>
#include <iterator>
#include <iostream>
#include <random>

#include "seal/seal.h"

using namespace std;
using namespace seal;

// size_t halfslots = 128; 

vector<uint64_t> get_symmetric_key();

vector<uint64_t> create_random_vector(size_t size);

vector<int64_t> create_random_int_vector(size_t size);

vector<Ciphertext> encrypt_symmetric_key(const vector<uint64_t> &ssk, bool batch_encoder, 
                                         const BatchEncoder &benc, const Encryptor &enc);

// Ciphertext encrypting(const vector<int64_t> &input, const PublicKey &he_pk, const BatchEncoder &benc, const Encryptor &enc);

Ciphertext encrypting(const vector<int64_t> &input, const PublicKey &he_pk, 
                      const BatchEncoder &benc, const Encryptor &enc);

vector<int64_t> decrypting(const Ciphertext &enc_input, const SecretKey &he_sk, 
                           const BatchEncoder &benc, const SEALContext &con, size_t size);

vector<int> add_gk_indices(bool use_bsgs, const BatchEncoder &benc);

void packed_enc_multiply(const Ciphertext &encrypted1,
                         const Ciphertext &encrypted2,
                         Ciphertext &destination, 
                         const Evaluator &evaluator);

void packed_enc_addition(const Ciphertext &encrypted1, 
                         const Ciphertext &encrypted2, 
                         Ciphertext &destination,
                         const Evaluator &evaluator);

template<typename T>
size_t get_full_mem_usage(const vector<T>& vec)
{
  size_t size_of_vector_struct = sizeof(vector<T>);
  size_t size_of_single_element = sizeof(T);
  return size_of_vector_struct + size_of_single_element * vec.capacity();
}

template<typename T>
size_t get_used_mem_usage(const vector<T>& vec)
{
  size_t size_of_vector_struct = sizeof(vector<T>);
  size_t size_of_single_element = sizeof(T);
  return size_of_vector_struct + size_of_single_element * vec.size();
}

void packed_plain_multiply(const Ciphertext &encrypted,
                           const Plaintext &plain,
                           Ciphertext &destination, 
                           const Evaluator &evaluator);

void packed_plain_addition(const Ciphertext &encrypted, 
                           const Plaintext &plain, 
                           Ciphertext &destination,
                           const Evaluator &evaluator);

Ciphertext create_random_encrypted_vector(size_t size, const PublicKey &he_pk, 
                                          const BatchEncoder &benc, const Encryptor &enc);

#endif
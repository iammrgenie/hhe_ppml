#pragma once

//Simplification of the PASTA HHE Implementation

#include "Cipher.h"
#include <seal/seal.h>

vector<Ciphertext> encrypt_key(bool batch_encoder, Encryptor E, BatchEncoder B, vector<uint64_t> in_key);


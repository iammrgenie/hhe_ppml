#include <sstream>

#include "seal/seal.h"
#include "sealhelper.h"

using namespace std;
using namespace seal;

stringstream parms_stream;

EncryptionParameters generate_seal_context(size_t poly_modulus_degree) {
    EncryptionParameters parms(scheme_type::bfv);
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    
    return parms;
}

tuple<SecretKey, PublicKey, RelinKeys> generate_keys(SEALContext context) {
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    return make_tuple(secret_key, public_key, relin_keys);
}

template <typename T> 
string save_stuff(T stuff) {
    stringstream stuff_stream;
    auto stuff_size = stuff.save(stuff_stream);
    string stuff_string = stuff_stream.str();
    return stuff_string;
}

Ciphertext encrypting(vector<int64_t> input, SEALContext context, PublicKey public_key) {
    // encode and encrypt the input
    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, public_key);
    Plaintext plain_input;
    batch_encoder.encode(input, plain_input);
    Ciphertext enc_input;
    encryptor.encrypt(plain_input, enc_input);
    return enc_input;
}

vector<int64_t> decrypting(Ciphertext enc_input, SEALContext context, SecretKey secret_key) {
    // decrypt and decode the encrypted input
    BatchEncoder batch_encoder(context);
    Decryptor decryptor(context, secret_key);
    Plaintext plain_input;
    decryptor.decrypt(enc_input, plain_input);
    vector<int64_t> vec_input;
    batch_encoder.decode(plain_input, vec_input);
    return vec_input;
}


int main() {
    print_example_banner("Analyst");

    print_line(__LINE__);
    cout << "generate HE parameters and context";
    EncryptionParameters parms = generate_seal_context(8192*2);
	SEALContext context(parms);
    print_parameters(context);
    // save the parms into string to be sent
    string parms_string = save_stuff(parms);
    cout << "save params into stringstream of size " << parms_string.size() << endl;
	cout << endl;

	print_line(__LINE__);
	cout << "generate 4 HE keys (secret, public, relinearization, evaluation)" << endl;
    SecretKey secret_key;
    PublicKey public_key;
    RelinKeys relin_keys;
    tie(secret_key, public_key, relin_keys) = generate_keys(context);
    // save the keys that need to be sent into string 
    string public_key_string = save_stuff(public_key);
    string relin_keys_string = save_stuff(relin_keys);
    cout << "save public key into stringstream of size " << public_key_string.size() << endl;
    cout << "save relin keys into stringstream of size " << relin_keys_string.size() << endl;
	cout << endl;

    print_line(__LINE__);
    cout << "get the encrypted weights and biases" << endl;
    vector<int64_t> vec_weights{17, 31, 24, 17, 16, 15, 32, 6, 12};  // dummy weights for now
    vector<int64_t> vec_biases{-5, -5, -5, -5, -5, -5, -5, -5, -5};  // dummy biases for now
	print_vec(vec_weights, vec_weights.size());
    print_vec(vec_biases, vec_biases.size());
    Ciphertext enc_w = encrypting(vec_weights, context, public_key);
    Ciphertext enc_b = encrypting(vec_biases, context, public_key);
    string enc_w_string = save_stuff(enc_w);
    string enc_b_string = save_stuff(enc_b);
    cout << "save encrypted weights into stringstream of size " << enc_w_string.size() << endl;
    cout << "save encrypted biases into stringstream of size " << enc_b_string.size() << endl;
    cout << endl;

    print_line(__LINE__);
    cout << "decrypt the weights and biases to check" << endl; 
    vector<int64_t> dec_weights = decrypting(enc_w, context, secret_key);
    vector<int64_t> dec_biases = decrypting(enc_b, context, secret_key);
    print_vec(dec_weights, vec_weights.size());
    print_vec(dec_biases, vec_biases.size());
}
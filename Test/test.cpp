#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main()
{
    // Define two integers to be added
    uint64_t a = 5;
    uint64_t b = 7;

    // Step 1: Set up encryption parameters and context
    EncryptionParameters params(scheme_type::bfv);
    
    // Increase poly_modulus_degree to 4096 (a power of two)
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    
    // Set plain_modulus to be compatible with batching
    params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // Create SEALContext (no need for shared_ptr, pass by reference)
    SEALContext context(params);

    // Step 2: Key generation
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    // Step 3: Create Encryptor, Evaluator, and Decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Step 4: Encode and encrypt the integers a and b
    BatchEncoder encoder(context);
    Plaintext plain_a, plain_b;
    encoder.encode(vector<uint64_t>{a}, plain_a);
    encoder.encode(vector<uint64_t>{b}, plain_b);

    Ciphertext encrypted_a, encrypted_b;
    encryptor.encrypt(plain_a, encrypted_a);
    encryptor.encrypt(plain_b, encrypted_b);

    cout << "Encrypted integers: " << a << " and " << b << endl;

    // Step 5: Perform homomorphic addition of the two encrypted values
    Ciphertext encrypted_result;
    evaluator.add(encrypted_a, encrypted_b, encrypted_result);

    // Step 6: Decrypt the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    // Step 7: Decode the result
    vector<uint64_t> result;
    encoder.decode(plain_result, result);

    cout << "Homomorphic addition result: " << result[0] << endl;

    // The missing closing brace
    return 0;
}


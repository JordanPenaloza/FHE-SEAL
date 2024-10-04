#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath> // for pow function

using namespace std;
using namespace seal;

int main()
{
    try
    {
        // Step 1: Set up CKKS encryption parameters
        EncryptionParameters params(scheme_type::ckks);

        // Set poly_modulus_degree (must be a power of 2, typically at least 8192 for CKKS)
        size_t poly_modulus_degree = 8192;
        params.set_poly_modulus_degree(poly_modulus_degree);

        // Use SEAL's recommended coeff_modulus for CKKS with poly_modulus_degree 8192
        params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

        // Scaling factor for CKKS scheme (power of 2, e.g., 2^40)
        double scale = pow(2.0, 40);

        // Step 2: Create SEALContext with parameter validation
        SEALContext context(params);

        // Step 3: Validate SEALContext and check if CKKS is supported
        auto context_data = context.key_context_data();
        if (!context_data)
        {
            throw logic_error("Invalid encryption parameters provided.");
        }

        if (!context_data->qualifiers().using_ckks)
        {
            throw logic_error("Unsupported scheme: CKKS is not properly set up.");
        }

        cout << "CKKS scheme is properly set up and encryption parameters are valid." << endl;

        // Step 4: Key generation
        KeyGenerator keygen(context);
        
        // Create public key
        PublicKey public_key;
        keygen.create_public_key(public_key);
        
        // Get secret key
        SecretKey secret_key = keygen.secret_key();
        
        // Create relinearization keys
        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);

        Encryptor encryptor(context, public_key);
        Decryptor decryptor(context, secret_key);
        Evaluator evaluator(context);
        CKKSEncoder encoder(context);

        // Step 5: Encode and encrypt floating-point numbers
        vector<double> input_values = { 12.5, 3.75 };
        Plaintext plain1, plain2;
        encoder.encode(input_values[0], scale, plain1);
        encoder.encode(input_values[1], scale, plain2);

        Ciphertext encrypted1, encrypted2;
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);

        // Step 6: Perform homomorphic addition
        Ciphertext encrypted_add;
        evaluator.add(encrypted1, encrypted2, encrypted_add);

        // Step 7: Perform homomorphic subtraction
        Ciphertext encrypted_sub;
        evaluator.sub(encrypted1, encrypted2, encrypted_sub);

        // Step 8: Perform homomorphic multiplication
        Ciphertext encrypted_mul;
        evaluator.multiply(encrypted1, encrypted2, encrypted_mul);
        evaluator.relinearize_inplace(encrypted_mul, relin_keys);
        evaluator.rescale_to_next_inplace(encrypted_mul);

        // Step 9: Perform homomorphic power (e.g., raise first number to power 2)
        Ciphertext encrypted_pow;
        evaluator.exponentiate(encrypted1, 2, relin_keys, encrypted_pow);

        // Step 10: Decrypt the results
        Plaintext plain_add, plain_sub, plain_mul, plain_pow;
        decryptor.decrypt(encrypted_add, plain_add);
        decryptor.decrypt(encrypted_sub, plain_sub);
        decryptor.decrypt(encrypted_mul, plain_mul);
        decryptor.decrypt(encrypted_pow, plain_pow);

        // Step 11: Decode the results
        vector<double> result_add, result_sub, result_mul, result_pow;
        encoder.decode(plain_add, result_add);
        encoder.decode(plain_sub, result_sub);
        encoder.decode(plain_mul, result_mul);
        encoder.decode(plain_pow, result_pow);

        // Step 12: Display results
        cout << "Floating-point addition result: " << result_add[0] << endl;
        cout << "Floating-point subtraction result: " << result_sub[0] << endl;
        cout << "Floating-point multiplication result: " << result_mul[0] << endl;
        cout << "Floating-point power (a^2) result: " << result_pow[0] << endl;
    }
    catch (const exception &e)
    {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}


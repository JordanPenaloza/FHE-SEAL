import seal
import math
import numpy as np  # Import numpy for array handling

# CKKS Parameters setup
parms = seal.EncryptionParameters(seal.scheme_type.ckks)

# Set the polynomial modulus degree and coefficient modulus
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(seal.CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))

# Create SEALContext
context = seal.SEALContext(parms)

# Key generation
keygen = seal.KeyGenerator(context)
public_key = seal.PublicKey()
keygen.create_public_key(public_key)

secret_key = keygen.secret_key()
relin_keys = seal.RelinKeys()
keygen.create_relin_keys(relin_keys)

# Set up Encryptor, Evaluator, Decryptor, and CKKSEncoder
encryptor = seal.Encryptor(context, public_key)
evaluator = seal.Evaluator(context)
decryptor = seal.Decryptor(context, secret_key)
encoder = seal.CKKSEncoder(context)

# Scale parameter (set precision)
scale = pow(2.0, 40)

# Input decimal numbers
decimal_1 = 5.7
decimal_2 = 3.3

# Encode and encrypt the decimal numbers
plaintext1 = encoder.encode(decimal_1, scale)
plaintext2 = encoder.encode(decimal_2, scale)

encrypted1 = encryptor.encrypt(plaintext1)
encrypted2 = encryptor.encrypt(plaintext2)

# Perform homomorphic addition
encrypted_add = evaluator.add(encrypted1, encrypted2)

# Perform homomorphic subtraction
encrypted_sub = evaluator.sub(encrypted1, encrypted2)

# Perform homomorphic multiplication
encrypted_mult = evaluator.multiply(encrypted1, encrypted2)
evaluator.relinearize_inplace(encrypted_mult, relin_keys)
evaluator.rescale_to_next_inplace(encrypted_mult)

# Perform homomorphic power (exponentiation of the first number)
encrypted_pow = evaluator.square(encrypted1)
evaluator.relinearize_inplace(encrypted_pow, relin_keys)  # Pass relin_keys as second argument
evaluator.rescale_to_next_inplace(encrypted_pow)

# Decrypt and decode the results
decrypted_add = decryptor.decrypt(encrypted_add)
decrypted_sub = decryptor.decrypt(encrypted_sub)
decrypted_mult = decryptor.decrypt(encrypted_mult)
decrypted_pow = decryptor.decrypt(encrypted_pow)

result_add = encoder.decode(decrypted_add)
result_sub = encoder.decode(decrypted_sub)
result_mult = encoder.decode(decrypted_mult)
result_pow = encoder.decode(decrypted_pow)

# Output the results
print(f"Addition result: {result_add[0]:.5f}")
print(f"Subtraction result: {result_sub[0]:.5f}")
print(f"Multiplication result: {result_mult[0]:.5f}")
print(f"Power (Square of {decimal_1}) result: {result_pow[0]:.5f}")


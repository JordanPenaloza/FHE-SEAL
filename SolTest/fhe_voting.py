import seal
import numpy as np

# --- Initialization and Key Setup ---

def setup_fhe():
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
    
    # Setup encoder, encryptor, decryptor, and evaluator
    encoder = seal.CKKSEncoder(context)
    encryptor = seal.Encryptor(context, public_key)
    evaluator = seal.Evaluator(context)
    decryptor = seal.Decryptor(context, secret_key)

    return context, public_key, secret_key, relin_keys, encoder, encryptor, evaluator, decryptor

# --- Voting Functions ---

def encrypt_vote(encoder, encryptor, vote_value, scale=pow(2.0, 40)):
    """Encrypt a single vote"""
    plaintext = encoder.encode(vote_value, scale)
    encrypted_vote = encryptor.encrypt(plaintext)
    return encrypted_vote

def add_encrypted_votes(evaluator, encrypted_vote1, encrypted_vote2):
    """Add two encrypted votes (homomorphic addition)"""
    encrypted_sum = evaluator.add(encrypted_vote1, encrypted_vote2)
    return encrypted_sum

def decrypt_result(decryptor, encoder, encrypted_result):
    """Decrypt and decode the aggregated votes"""
    decrypted = decryptor.decrypt(encrypted_result)
    result = encoder.decode(decrypted)
    return result[0]

# --- Example Usage ---

if __name__ == "__main__":
    # Initialize FHE setup
    context, public_key, secret_key, relin_keys, encoder, encryptor, evaluator, decryptor = setup_fhe()
    
    # Example: Encrypt two votes (1 for candidate A and 1 for candidate B)
    vote_candidate_a = 1.0  # Representing a vote for candidate A
    vote_candidate_b = 1.0  # Representing a vote for candidate B
    
    encrypted_vote_a = encrypt_vote(encoder, encryptor, vote_candidate_a)
    encrypted_vote_b = encrypt_vote(encoder, encryptor, vote_candidate_b)
    
    # Perform homomorphic addition of votes
    encrypted_sum = add_encrypted_votes(evaluator, encrypted_vote_a, encrypted_vote_b)
    
    # Decrypt and display the result
    result = decrypt_result(decryptor, encoder, encrypted_sum)
    print(f"Aggregated (Decrypted) Vote Count: {result:.5f}")

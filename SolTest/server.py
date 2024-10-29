from flask import Flask, request, jsonify
import seal
import numpy as np
from fhe_voting import setup_fhe, encrypt_vote, add_encrypted_votes, decrypt_result

app = Flask(__name__)

# Initialize FHE setup
context, public_key, secret_key, relin_keys, encoder, encryptor, evaluator, decryptor = setup_fhe()

# Storage for encrypted votes
encrypted_votes = []

@app.route("/submit_vote", methods=["POST"])
def submit_vote():
    """Receive an encrypted vote and store it."""
    data = request.json
    vote_value = data.get("vote_value", 1.0)  # Default vote value is 1.0

    # Encrypt the vote
    encrypted_vote = encrypt_vote(encoder, encryptor, vote_value)
    encrypted_votes.append(encrypted_vote)
    
    return jsonify({"status": "Vote submitted successfully."}), 200

@app.route("/tally_votes", methods=["GET"])
def tally_votes():
    """Aggregate encrypted votes and return decrypted result."""
    if not encrypted_votes:
        return jsonify({"error": "No votes to tally."}), 400

    # Initialize the aggregated sum with the first encrypted vote
    encrypted_sum = encrypted_votes[0]
    
    # Add up all encrypted votes
    for vote in encrypted_votes[1:]:
        encrypted_sum = add_encrypted_votes(evaluator, encrypted_sum, vote)

    # Decrypt the aggregated result
    result = decrypt_result(decryptor, encoder, encrypted_sum)
    
    # Round to the nearest whole number and return
    rounded_result = round(result)
    
    return jsonify({"tally_result": int(rounded_result)}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

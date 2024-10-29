from web3 import Web3
import requests
from fhe_voting import setup_fhe, encrypt_vote, decrypt_result, add_encrypted_votes

# Use the Alchemy Sepolia RPC URL
alchemy_url = "https://eth-sepolia.alchemyapi.io/v2/EHoyWWNZcGvp32NzL-IB8E9vxyCIPqMs"
w3 = Web3(Web3.HTTPProvider(alchemy_url))

# Contract address and ABI (replace with your actual contract address and ABI)
contract_address = "YOUR_CONTRACT_ADDRESS"
contract_abi = [
    # Paste the ABI JSON from Remix here
]

# Initialize contract
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Fetch encrypted votes from the contract
def get_encrypted_votes():
    return contract.functions.getEncryptedVotes().call()

# Tally votes using FHE
def tally_votes(encrypted_votes):
    context, public_key, secret_key, relin_keys, encoder, encryptor, evaluator, decryptor = setup_fhe()
    
    # Convert the encrypted votes to SEAL format and add them
    encrypted_sum = None
    for vote in encrypted_votes:
        encrypted_vote = encrypt_vote(encoder, encryptor, float(vote))  # Assuming each vote is float-compatible
        encrypted_sum = encrypted_vote if encrypted_sum is None else add_encrypted_votes(evaluator, encrypted_sum, encrypted_vote)
    
    # Decrypt the tally
    result = decrypt_result(decryptor, encoder, encrypted_sum)
    rounded_result = round(result)

    # Send tally to the HTTP server (optional for verification)
    response = requests.get("http://localhost:5000/tally_votes")
    print("Tally from server:", response.json())
    print("Tally from Python tally:", rounded_result)

    return rounded_result

if __name__ == "__main__":
    # Retrieve votes from the blockchain
    encrypted_votes = get_encrypted_votes()
    print("Fetched encrypted votes:", encrypted_votes)
    
    # Tally votes and print result
    tally_result = tally_votes(encrypted_votes)
    print("Final Tally Result:", tally_result)

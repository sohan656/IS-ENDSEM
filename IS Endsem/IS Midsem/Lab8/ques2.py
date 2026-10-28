
from phe import paillier
import hashlib
import re

# Dataset of 10 documents
documents = {
    "doc1": "python is used for programming",
    "doc2": "cryptography provides data security",
    "doc3": "python supports cryptography",
    "doc4": "encryption protects sensitive data",
    "doc5": "machine learning uses python",
    "doc6": "network security is important",
    "doc7": "python makes programming easier",
    "doc8": "cryptography uses encryption algorithms",
    "doc9": "data security protects information",
    "doc10": "python and encryption are useful"
}

# Generate Paillier public and private keys
def generate_keys():
    public_key, private_key = paillier.generate_paillier_keypair()
    return public_key, private_key

# Encryption
def encrypt_data(public_key, data):
    return public_key.encrypt(data)

# Decryption
def decrypt_data(private_key, ciphertext):
    return private_key.decrypt(ciphertext)

# Convert a word into a small integer identifier
# This mapping is public and is for demonstration only.
def word_to_int(word):
    hash_value = hashlib.sha256(word.encode()).digest()
    return int.from_bytes(hash_value[:8], "big")

# Create encrypted inverted index
def create_index(documents, public_key):
    index = []

    for doc_id, document in documents.items():
        words = set(re.findall(r"\w+", document.lower()))

        for word in sorted(words):
            word_id = word_to_int(word)

            encrypted_word = encrypt_data(
                public_key, word_id
            )

            encrypted_doc_id = encrypt_data(
                public_key, int(doc_id[3:])
            )

            index.append((encrypted_word, encrypted_doc_id))

    return index

# Search encrypted index
def search(encrypted_index, query, public_key, private_key):
    query_id = word_to_int(query.lower())

    # Encrypt the search query
    encrypted_query = encrypt_data(public_key, query_id)

    results = set()

    for encrypted_word, encrypted_doc_id in encrypted_index:

        # Homomorphic subtraction:
        # E(word) - E(query) = E(word - query)
        encrypted_difference = encrypted_word - encrypted_query

        # Authorized client checks for equality
        difference = decrypt_data(
            private_key, encrypted_difference
        )

        if difference == 0:
            doc_id = decrypt_data(
                private_key, encrypted_doc_id
            )
            results.add("doc" + str(doc_id))

    return sorted(results, key=lambda x: int(x[3:]))

# Main program
public_key, private_key = generate_keys()

encrypted_index = create_index(documents, public_key)

query = "python"

print("Search Query:", query)

encrypted_query = encrypt_data(
    public_key, word_to_int(query)
)

print("Encrypted Query:", encrypted_query.ciphertext())

results = search(
    encrypted_index, query, public_key, private_key
)

print("\nMatching Document IDs:", results)

print("\nMatching Documents:")
for doc_id in results:
    print(doc_id, ":", documents[doc_id])

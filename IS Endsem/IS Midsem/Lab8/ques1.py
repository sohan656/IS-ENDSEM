
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
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

# AES encryption
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(
        pad(data.encode(), AES.block_size)
    )
    return cipher.iv + ciphertext

# AES decryption
def decrypt_data(key, encrypted_data):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(
        cipher.decrypt(ciphertext), AES.block_size
    ).decode()

# Generate a deterministic secret search token
def create_token(key, word):
    return hmac.new(
        key, word.encode(), hashlib.sha256
    ).digest()

# Create encrypted inverted index
def create_index(documents, aes_key, search_key):
    index = {}

    for doc_id, document in documents.items():
        for word in set(re.findall(r"\w+", document.lower())):
            token = create_token(search_key, word)

            if token not in index:
                index[token] = []

            index[token].append(
                encrypt_data(aes_key, doc_id)
            )

    return index

# Search encrypted index
def search(encrypted_index, query, aes_key, search_key):
    token = create_token(search_key, query.lower())

    if token in encrypted_index:
        return [
            decrypt_data(aes_key, encrypted_id)
            for encrypted_id in encrypted_index[token]
        ]

    return []

# Main program
aes_key = get_random_bytes(16)
search_key = get_random_bytes(32)

encrypted_index = create_index(
    documents, aes_key, search_key
)

query = "python"

print("Search Query:", query)
print("Encrypted Search Token:",
      create_token(search_key, query).hex())

results = search(
    encrypted_index, query, aes_key, search_key
)

print("\nMatching Document IDs:", results)

print("\nMatching Documents:")
for doc_id in results:
    print(doc_id, ":", documents[doc_id])

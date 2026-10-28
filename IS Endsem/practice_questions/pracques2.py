'''
Question 2: Secure Banking and Fund Transfer System
20 marks
A bank named TrustBank wants to secure communications between its headquarters and branch offices.

The system must protect financial transactions, establish secure keys between branches and verify whether transaction files have been modified.

Requirements:
1. Diffie-Hellman Key Exchange (4 marks): Two branches must generate a common secret over an insecure channel without transmitting the secret itself.
2. AES-GCM Encryption (4 marks): Derive an AES key from the shared secret and encrypt transaction details.
3. RSA Encryption (3 marks): Encrypt a short confidential authorization message using RSA-OAEP and decrypt it.
4. SHA-256 Integrity (3 marks): Save a transaction to a file, calculate its hash and detect modification.
5. Integration (3 marks): Implement all operations using a menu.
6. Documentation (3 marks): Explain the security mechanisms.
'''


import hashlib
import json
import secrets

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Util.number import getPrime, isPrime


# ------------------------------------------
# 1. DIFFIE-HELLMAN KEY EXCHANGE
# ------------------------------------------

def diffie_hellman():
    # Safe-prime group for demonstration
    q = getPrime(256)
    p = 2 * q + 1

    while not isPrime(p):
        q = getPrime(256)
        p = 2 * q + 1

    g = 4

    a = secrets.randbelow(q - 1) + 1
    b = secrets.randbelow(q - 1) + 1

    A = pow(g, a, p)
    B = pow(g, b, p)

    shared_a = pow(B, a, p)
    shared_b = pow(A, b, p)

    assert shared_a == shared_b

    shared_bytes = shared_a.to_bytes(
        (p.bit_length() + 7) // 8, "big"
    )

    # Derive AES-256 key
    aes_key = HKDF(
        shared_bytes, 32, b"TrustBank-v1", SHA256
    )

    print("Shared keys match:", shared_a == shared_b)
    return aes_key


# ------------------------------------------
# 2. AES-GCM ENCRYPTION
# ------------------------------------------

def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(
        message.encode()
    )

    return cipher.nonce, ciphertext, tag


def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    return cipher.decrypt_and_verify(
        ciphertext, tag
    ).decode()


# ------------------------------------------
# 3. RSA-OAEP ENCRYPTION
# ------------------------------------------

rsa_key = RSA.generate(2048)


def rsa_encrypt(message):
    cipher = PKCS1_OAEP.new(
        rsa_key.publickey(),
        hashAlgo=SHA256
    )
    return cipher.encrypt(message.encode())


def rsa_decrypt(ciphertext):
    cipher = PKCS1_OAEP.new(
        rsa_key, hashAlgo=SHA256
    )
    return cipher.decrypt(ciphertext).decode()


# ------------------------------------------
# 4. FILE INTEGRITY
# ------------------------------------------

def file_integrity():
    original = "TX101|Rahul|5000|Completed"

    with open("transaction.txt", "w") as f:
        f.write(original)

    with open("transaction.txt", "rb") as f:
        original_hash = hashlib.sha256(f.read()).hexdigest()

    print("Original hash:", original_hash)

    # Simulate unauthorized modification
    with open("transaction.txt", "w") as f:
        f.write("TX101|Rahul|9000|Completed")

    with open("transaction.txt", "rb") as f:
        modified_hash = hashlib.sha256(f.read()).hexdigest()

    print("Modified hash:", modified_hash)

    if original_hash == modified_hash:
        print("Integrity verified")
    else:
        print("Tampering detected")


# ------------------------------------------
# 5. MAIN MENU
# ------------------------------------------

def main():
    aes_key = None

    while True:
        print("\n--- TRUSTBANK ---")
        print("1. Diffie-Hellman Key Exchange")
        print("2. AES Secure Transaction")
        print("3. RSA Confidential Message")
        print("4. File Integrity")
        print("5. Exit")

        choice = input("Choice: ")

        try:
            if choice == "1":
                aes_key = diffie_hellman()

            elif choice == "2":
                if aes_key is None:
                    print("Establish shared key first")
                    continue

                message = input("Transaction: ")

                nonce, ct, tag = aes_encrypt(
                    message, aes_key
                )

                print("Ciphertext:", ct.hex())
                print("Decrypted:", aes_decrypt(
                    nonce, ct, tag, aes_key
                ))

            elif choice == "3":
                message = input("Authorization message: ")

                ct = rsa_encrypt(message)

                print("Encrypted:", ct.hex())
                print("Decrypted:", rsa_decrypt(ct))

            elif choice == "4":
                file_integrity()

            elif choice == "5":
                break

            else:
                print("Invalid choice")

        except (ValueError, KeyError) as e:
            print("Error:", e)


if __name__ == "__main__":
    main()

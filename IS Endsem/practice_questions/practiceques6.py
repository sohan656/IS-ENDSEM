'''
Question 2: Secure Cloud Storage with Automatic Key Rotation
20 marks
New concepts: Key versioning, key renewal, key revocation and secure deletion

A cloud storage company stores confidential customer documents using AES encryption.

The organization wants a centralized key management system that generates, renews and revokes encryption keys.
Requirements
1. Key Generation (3 marks): Generate AES-256 keys using PBKDF2 with 15 iterations and a random salt.
2. Key Versioning (3 marks): Assign a unique version number to each generated key, such as K1, K2, K3.
3. Automatic Key Rotation (4 marks): Rotate the active key every 90 seconds and re-encrypt stored documents using the new key.
4. Key Revocation (3 marks): Allow the administrator to revoke a compromised key. Reject further encryption or decryption using the revoked key.
5. RSA Digital Signature (3 marks): Sign each document using RSA-2048 and SHA-256, and verify the signature before decryption.
6. Audit Logging and Integration (4 marks): Record key generation, rotation, expiry, revocation and unauthorized access attempts.
'''


import time

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes


PASSWORD = b"CloudLabPassword"

keys = {}
documents = {}
audit_log = []

key_version = 0
rsa_key = RSA.generate(2048)


def audit(action, details=""):
    entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "details": details
    }

    audit_log.append(entry)
    print("[AUDIT]", entry)


# Generate a new versioned AES-256 key
def generate_key():
    global key_version

    key_version += 1
    key_id = f"K{key_version}"

    salt = get_random_bytes(16)

    key = PBKDF2(
        PASSWORD,
        salt,
        dkLen=32,              # AES-256 key
        count=15,              # 15 KDF iterations
        hmac_hash_module=SHA256
    )

    created = time.time()

    keys[key_id] = {
        "key": key,
        "salt": salt,
        "created": created,
        "expiry": created + 90,
        "revoked": False
    }

    audit("KEY_GENERATED", key_id)
    return key_id


# Check expiry and revocation status
def key_valid(key_id):
    info = keys.get(key_id)

    if info is None:
        return False

    if info["revoked"]:
        return False

    if time.time() >= info["expiry"]:
        audit("KEY_EXPIRED", key_id)
        return False

    return True


# Encrypt bytes using AES-GCM
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(data)

    return cipher.nonce, ciphertext, tag


# Decrypt and verify AES-GCM ciphertext
def aes_decrypt(package, key):
    nonce, ciphertext, tag = package

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    return cipher.decrypt_and_verify(ciphertext, tag)


# Generate RSA PKCS#1 v1.5 signature
def sign_document(data):
    digest = SHA256.new(data)
    return pkcs1_15.new(rsa_key).sign(digest)


# Verify signature with RSA public key
def verify_document(data, signature):
    digest = SHA256.new(data)

    try:
        pkcs1_15.new(rsa_key.publickey()).verify(
            digest, signature
        )
        return True

    except (ValueError, TypeError):
        return False


# Create and encrypt a cloud document
def add_document():
    doc_id = input("Document ID: ").strip()

    if not doc_id or doc_id in documents:
        print("Invalid or duplicate ID")
        return

    content = input("Document content: ").encode()

    key_id = generate_key()
    key = keys[key_id]["key"]

    package = aes_encrypt(content, key)
    signature = sign_document(content)

    documents[doc_id] = {
        "key_id": key_id,
        "package": package,
        "signature": signature
    }

    print("Document encrypted using:", key_id)
    print("Signature:", signature.hex())

    audit("DOCUMENT_CREATED", doc_id)


# Decrypt a single document
def view_document():
    doc_id = input("Document ID: ").strip()

    if doc_id not in documents:
        print("Document not found")
        return

    doc = documents[doc_id]
    key_id = doc["key_id"]

    if not key_valid(key_id):
        print("Key expired or revoked")
        return

    try:
        plaintext = aes_decrypt(
            doc["package"],
            keys[key_id]["key"]
        )

        valid = verify_document(
            plaintext,
            doc["signature"]
        )

        print("Signature valid:", valid)

        if valid:
            print("Content:", plaintext.decode())
            audit("DOCUMENT_VIEWED", doc_id)

    except ValueError:
        audit("TAMPERING_DETECTED", doc_id)
        print("Authentication failed")


# Rotate the key of a document
def rotate_document():
    doc_id = input("Document ID: ").strip()

    if doc_id not in documents:
        print("Document not found")
        return

    doc = documents[doc_id]
    old_id = doc["key_id"]

    # The old key must still be usable for re-encryption
    if not key_valid(old_id):
        print("Old key unavailable. Rotation denied.")
        return

    try:
        plaintext = aes_decrypt(
            doc["package"],
            keys[old_id]["key"]
        )

        if not verify_document(plaintext, doc["signature"]):
            print("Invalid document signature")
            return

    except ValueError:
        audit("TAMPERING_DETECTED", doc_id)
        return

    new_id = generate_key()

    doc["package"] = aes_encrypt(
        plaintext,
        keys[new_id]["key"]
    )

    doc["key_id"] = new_id

    # Old key is no longer used by this document
    keys[old_id]["revoked"] = True

    audit("KEY_ROTATED", f"{doc_id}: {old_id} -> {new_id}")


# Revoke a selected key
def revoke_key():
    key_id = input("Key ID: ").strip()

    if key_id not in keys:
        print("Key not found")
        return

    keys[key_id]["revoked"] = True
    audit("KEY_REVOKED", key_id)


# Modify ciphertext to demonstrate detection
def tamper_document():
    doc_id = input("Document ID: ").strip()

    if doc_id not in documents:
        print("Document not found")
        return

    nonce, ciphertext, tag = documents[doc_id]["package"]

    modified = bytearray(ciphertext)

    if modified:
        modified[0] ^= 1   # Flip one ciphertext bit
    else:
        tag = bytes([tag[0] ^ 1]) + tag[1:]

    documents[doc_id]["package"] = (
        nonce,
        bytes(modified),
        tag
    )

    audit("DOCUMENT_TAMPERED", doc_id)


def show_audit():
    for entry in audit_log:
        print(entry)


def main():
    while True:
        print("\n--- CLOUD STORAGE ---")
        print("1. Add Document")
        print("2. View Document")
        print("3. Rotate Document Key")
        print("4. Revoke Key")
        print("5. Tamper Document (Demo)")
        print("6. View Audit")
        print("7. Exit")

        choice = input("Choice: ")

        if choice == "1":
            add_document()

        elif choice == "2":
            view_document()

        elif choice == "3":
            rotate_document()

        elif choice == "4":
            revoke_key()

        elif choice == "5":
            tamper_document()

        elif choice == "6":
            show_audit()

        elif choice == "7":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

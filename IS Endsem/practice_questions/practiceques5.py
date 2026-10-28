'''
Question 1: Secure Military Document Management
20 marks
New concepts: Bell–LaPadula, ABAC, time-based access and key rotation

A defense organization maintains confidential documents classified as Public, Confidential, Secret and Top Secret.

Each employee has a security clearance and belongs to a department.

The organization wants to protect documents using encryption and enforce strict access policies.
Requirements
1. AES-256 Encryption (3 marks): Encrypt documents using AES-CBC. Generate the encryption key using PBKDF2 with 20 iterations.
2. Bell-LaPadula Access Control (4 marks): Implement:
   - No Read Up: Employees cannot read documents above their clearance.
   - No Write Down: Employees cannot write to documents below their clearance.
3. Attribute-Based Access Control (3 marks): Grant access only when the employee belongs to the appropriate department and has the required clearance.
4. Time-Based Access (3 marks): Permit document decryption only during an authorized access window of 60 seconds.
5. Key Rotation and Audit Logging (4 marks): Rotate encryption keys after 3 successful document accesses. Re-encrypt documents using the new key and record the rotation.
6. Integration (3 marks): Implement an interactive menu and display access-denied events.
'''


import time

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


# Classification levels used for access comparisons
LEVELS = {
    "Public": 1,
    "Confidential": 2,
    "Secret": 3,
    "Top Secret": 4
}

PASSWORD = b"MilitaryLabPassword"

# Employee details
users = {
    "E101": {"department": "Intel", "clearance": "Secret"},
    "E102": {"department": "Intel", "clearance": "Top Secret"},
    "E103": {"department": "Intel", "clearance": "Confidential"},
    "E104": {"department": "Operations", "clearance": "Top Secret"}
}

documents = {}
audit_log = []


# Record an operation with its timestamp
def audit(action, details):
    entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "details": details
    }

    audit_log.append(entry)
    print("[AUDIT]", entry)


# Generate a 32-byte AES-256 key
def derive_key(salt):
    return PBKDF2(
        PASSWORD,
        salt,
        dkLen=32,              # 32 bytes for AES-256
        count=20,              # 20 KDF iterations required
        hmac_hash_module=SHA256
    )


# Encrypt text using AES-256 CBC
def encrypt_text(text, key):
    cipher = AES.new(key, AES.MODE_CBC)

    # Convert text to bytes and add block padding
    ciphertext = cipher.encrypt(
        pad(text.encode(), AES.block_size)
    )

    return cipher.iv, ciphertext


# Decrypt text using the original IV
def decrypt_text(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    return unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    ).decode()


# Check the user's department and clearance
def check_access(user_id, doc_id, operation):
    user = users.get(user_id)
    doc = documents.get(doc_id)

    if user is None or doc is None:
        return False

    # ABAC: department must match
    if user["department"] != doc["department"]:
        return False

    user_level = LEVELS[user["clearance"]]
    doc_level = LEVELS[doc["classification"]]

    if operation == "read":
        return user_level >= doc_level   # No Read Up

    if operation == "write":
        return user_level <= doc_level   # No Write Down

    return False


# Create and encrypt a new document
def create_document():
    doc_id = input("Document ID: ").strip()

    if not doc_id or doc_id in documents:
        print("Invalid or duplicate document ID")
        return

    department = input("Department: ").strip()
    classification = input("Classification: ").strip()
    content = input("Document content: ")

    if department not in ("Intel", "Operations"):
        print("Invalid department")
        return

    if classification not in LEVELS:
        print("Invalid classification")
        return

    salt = get_random_bytes(16)
    key = derive_key(salt)

    iv, ciphertext = encrypt_text(content, key)

    documents[doc_id] = {
        "department": department,
        "classification": classification,
        "salt": salt,
        "iv": iv,
        "ciphertext": ciphertext,
        "created": time.time(),
        "expiry": time.time() + 60,  # 60-second access window
        "access_count": 0,
        "version": 1
    }

    audit("DOCUMENT_CREATED", doc_id)


# Replace the encryption key after three accesses
def rotate_key(doc_id):
    doc = documents[doc_id]

    old_key = derive_key(doc["salt"])

    # Recover the current document before changing keys
    plaintext = decrypt_text(
        doc["iv"],
        doc["ciphertext"],
        old_key
    )

    new_salt = get_random_bytes(16)
    new_key = derive_key(new_salt)

    new_iv, new_ciphertext = encrypt_text(
        plaintext,
        new_key
    )

    doc["salt"] = new_salt
    doc["iv"] = new_iv
    doc["ciphertext"] = new_ciphertext

    doc["version"] += 1
    doc["access_count"] = 0

    audit("KEY_ROTATED", f"{doc_id}, version {doc['version']}")


# Read or modify a document
def access_document(operation):
    user_id = input("Employee ID: ").strip()
    doc_id = input("Document ID: ").strip()

    if not check_access(user_id, doc_id, operation):
        audit("ACCESS_DENIED", f"{user_id}: {doc_id}")
        return

    doc = documents[doc_id]

    # Reject access once the 60-second window has ended
    if time.time() >= doc["expiry"]:
        audit("ACCESS_EXPIRED", doc_id)
        return

    key = derive_key(doc["salt"])

    plaintext = decrypt_text(
        doc["iv"],
        doc["ciphertext"],
        key
    )

    if operation == "read":
        print("Document:", plaintext)

    elif operation == "write":
        new_content = input("New content: ")

        doc["iv"], doc["ciphertext"] = encrypt_text(
            new_content,
            key
        )

        audit("DOCUMENT_UPDATED", doc_id)

    doc["access_count"] += 1

    audit("ACCESS_GRANTED", f"{user_id}: {operation}")

    if doc["access_count"] >= 3:
        rotate_key(doc_id)


def show_audit():
    for entry in audit_log:
        print(entry)


def main():
    while True:
        print("\n--- MILITARY DOCUMENT MANAGEMENT ---")
        print("1. Create Document")
        print("2. Read Document")
        print("3. Write Document")
        print("4. View Audit Log")
        print("5. Exit")

        choice = input("Choice: ")

        try:
            if choice == "1":
                create_document()

            elif choice == "2":
                access_document("read")

            elif choice == "3":
                access_document("write")

            elif choice == "4":
                show_audit()

            elif choice == "5":
                break

            else:
                print("Invalid choice")

        except (ValueError, KeyError) as e:
            print("Error:", e)


if __name__ == "__main__":
    main()


# functionality to renew the access window for a document
def renew_access():
    doc_id = input("Document ID: ").strip()

    if doc_id not in documents:
        print("Document not found")
        return

    # Extend access for another 60 seconds
    documents[doc_id]["expiry"] = time.time() + 60

    audit("ACCESS_RENEWED", doc_id)

    print("Access renewed for 60 seconds")
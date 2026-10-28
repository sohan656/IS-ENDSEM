'''
You are tasked with developing a secure education data management system called EduSecure. This system ensures that students' academic records are stored confidentially, accessed only by authorized users, and verified for authenticity. The system supports three types of users: Students, Faculties, and HoDs, each with specific roles and permissions.

The platform uses DES symmetric encryption for storing sensitive academic records, RSAdigital signatures for authenticating users, and SHA-256 hashing to verify record integrity.

User Roles & Permissions

Student:

• Encrypts a student's academic records (for example: - ISL-5CCE-A2.txt) using DES before uploading.

• Signs the SHA-256 hash of the encrypted record using his/her RSA private key.

• Can view past uploaded records and his/her encrypted/hashed forms with timestamps.

Faculty:

• Decrypts the student's records using the shared DES key.

• Verifies RSA signatures of the students to ensure authenticity.

• Computes SHA-256 hash of decrypted records and compares with the stored hash.

• Stores verification results with timestamps.

HoD:

• Can view only the hashed academic records with timestamps.

• Verifies RSA signatures on stored records for accreditation purposes.

Access Roles:

• Allow Students to encrypt records with DES, sign using RSA, and upload securely.

• Enable Faculties to decrypt with DES, verify RSA signatures, and hash the records.

• Allow HoDs to view only hashes and verify signatures.

Task:

Develop a menu-driven Python program that implements these functionalities using:

• DES symmetric encryption,

• RSA digital signatures, and

• SHA-256 hashing.

Ensure secure handling of academic records and proper role-based access. Use any file or database structure to store and retrieve the records securely
'''


import hashlib
import base64
from datetime import datetime

from Cryptodome.Cipher import DES
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


# ==========================================================
# KEYS
# ==========================================================

des_key = get_random_bytes(8)

rsa_key = RSA.generate(2048)
private_key = rsa_key
public_key = rsa_key.publickey()


# ==========================================================
# STORAGE
# ==========================================================

records = {}


# ==========================================================
# SHA-256 HASH
# ==========================================================

def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ==========================================================
# DES ENCRYPTION
# ==========================================================

def encrypt_des(data):
    cipher = DES.new(des_key, DES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(data, DES.block_size)
    )

    # Store IV along with ciphertext
    return cipher.iv + ciphertext


# ==========================================================
# DES DECRYPTION
# ==========================================================

def decrypt_des(data):
    iv = data[:8]
    ciphertext = data[8:]

    cipher = DES.new(
        des_key,
        DES.MODE_CBC,
        iv=iv
    )

    plaintext = cipher.decrypt(ciphertext)

    return unpad(
        plaintext,
        DES.block_size
    )


# ==========================================================
# RSA SIGNATURE
# ==========================================================

def sign_hash(hash_value):

    hash_bytes = bytes.fromhex(hash_value)

    digest = SHA256.new(hash_bytes)

    signature = pkcs1_15.new(
        private_key
    ).sign(digest)

    return base64.b64encode(signature).decode()


# ==========================================================
# RSA SIGNATURE VERIFICATION
# ==========================================================

def verify_signature(hash_value, signature):

    try:
        hash_bytes = bytes.fromhex(hash_value)

        digest = SHA256.new(hash_bytes)

        signature = base64.b64decode(signature)

        pkcs1_15.new(
            public_key
        ).verify(
            digest,
            signature
        )

        return True

    except Exception:
        return False


# ==========================================================
# STUDENT
# ==========================================================

def student():

    print("\n===== STUDENT =====")

    student_id = input("Enter Student ID: ")
    filename = input("Enter record filename: ")

    try:
        # Read academic record file
        with open(filename, "rb") as file:
            record = file.read()

    except FileNotFoundError:
        print("File not found.")
        return
    
    

    # 1. Hash original record
    original_hash = sha256(record)

    # 2. Encrypt record using DES
    encrypted_record = encrypt_des(record)

    # 3. Hash encrypted record
    encrypted_hash = sha256(encrypted_record)

    # 4. Sign encrypted hash using RSA private key
    signature = sign_hash(encrypted_hash)

    # 5. Store record
    records[student_id] = {
        "filename": filename,
        "encrypted_record": encrypted_record,
        "original_hash": original_hash,
        "encrypted_hash": encrypted_hash,
        "signature": signature,
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    print("\nRecord uploaded successfully.")


# ==========================================================
# VIEW PAST UPLOADED RECORDS
# ==========================================================

def view_records():

    if not records:
        print("\nNo uploaded records.")
        return

    print("\n===== PAST UPLOADED RECORDS =====")

    for student_id, record in records.items():

        print("\nStudent ID:", student_id)
        print("Filename:", record["filename"])
        print("Encrypted SHA-256:", record["encrypted_hash"])
        print("Timestamp:", record["timestamp"])


# ==========================================================
# FACULTY 
# ==========================================================

def faculty():

    print("\n===== FACULTY =====")

    student_id = input("Enter Student ID: ")

    if student_id not in records:
        print("Record not found.")
        return

    record = records[student_id]

    # 1. Verify encrypted record hash
    calculated_encrypted_hash = sha256(
        record["encrypted_record"]
    )

    if calculated_encrypted_hash == record["encrypted_hash"]:
        print("\nEncrypted Hash: VALID")
    else:
        print("\nEncrypted Hash: INVALID")
        return

    # 2. Verify RSA signature
    if verify_signature(
        record["encrypted_hash"],
        record["signature"]
    ):
        print("RSA Signature: VALID")
    else:
        print("RSA Signature: INVALID")
        return

    # 3. Decrypt record
    try:
        decrypted_record = decrypt_des(
            record["encrypted_record"]
        )

        print("DES Decryption: SUCCESS")

    except Exception:
        print("DES Decryption: FAILED")
        return

    # 4. Hash decrypted record
    calculated_hash = sha256(decrypted_record)

    if calculated_hash == record["original_hash"]:
        print("Decrypted Record Hash: VALID")
    else:
        print("Decrypted Record Hash: INVALID")
        return

    # Display decrypted record
    print("\nDecrypted Record:")
    print(decrypted_record.decode())


# ==========================================================
# HOD
# ==========================================================

def hod():

    print("\n===== HOD =====")

    student_id = input("Enter Student ID: ")

    if student_id not in records:
        print("Record not found.")
        return

    record = records[student_id]

    # HoD can only see hashes and timestamp
    print("\nOriginal SHA-256:")
    print(record["original_hash"])

    print("\nEncrypted SHA-256:")
    print(record["encrypted_hash"])

    print("\nTimestamp:")
    print(record["timestamp"])

    # Verify RSA signature
    if verify_signature(
        record["encrypted_hash"],
        record["signature"]
    ):
        print("\nRSA Signature: VALID")
    else:
        print("\nRSA Signature: INVALID")


# ==========================================================
# MAIN MENU
# ==========================================================

while True:

    print("\n===================================")
    print("              EDUSECURE")
    print("===================================")
    print("1. Student")
    print("2. Faculty")
    print("3. HoD")
    print("4. Exit")

    choice = input("Enter choice: ")

    if choice == "1":

        student()

        # Student can view past uploaded records
        view_records()

    elif choice == "2":

        faculty()

    elif choice == "3":

        hod()

    elif choice == "4":

        print("Exiting...")
        break

    else:

        print("Invalid choice.")


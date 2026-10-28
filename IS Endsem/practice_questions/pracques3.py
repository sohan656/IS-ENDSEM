'''
Question 3: Secure University Examination Management System
20 marks
A university wants to develop a secure result management application.

The university has the following student records:
ID	    Name	Department	Marks
ST101	Rahul	ICT	        85
ST102	Asha	CSE	        92
ST103	Kiran	ICT	        78
ST104	Divya	ECE	        88

Requirements:
1. AES Encryption (3 marks): Encrypt student records and decrypt them only when access is permitted.
2. Role-Based Access Control (4 marks): Implement Admin, Faculty and Student roles. Admin can view all records, Faculty can view students in their department, and Student can view only their own result.
3. RSA Digital Signatures (3 marks): Sign a result and verify whether its marks have been modified.
4. Key Management (3 marks): Implement key revocation and renewal.
5. Hashing (2 marks): Detect modifications using SHA-256.
6. Documentation and Integration (5 marks): Implement a menu-driven application and explain its working.
'''


import hashlib

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes


students = {
    "ST101": ["Rahul", "ICT", 85],
    "ST102": ["Asha", "CSE", 92],
    "ST103": ["Kiran", "ICT", 78],
    "ST104": ["Divya", "ECE", 88]
}

aes_key = get_random_bytes(32)
rsa_key = RSA.generate(2048)

encrypted_records = {}
key_active = True


# ------------------------------------------
# 1. AES ENCRYPTION
# ------------------------------------------

def encrypt(message):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(
        message.encode()
    )
    return cipher.nonce, ciphertext, tag


def decrypt(package):
    if not key_active:
        raise PermissionError("Key has been revoked")

    nonce, ct, tag = package
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    return cipher.decrypt_and_verify(ct, tag).decode()


def record_text(sid):
    s = students[sid]
    return f"{sid}|{s[0]}|{s[1]}|{s[2]}"


def encrypt_all():
    encrypted_records.clear()

    for sid in students:
        encrypted_records[sid] = encrypt(record_text(sid))


# ------------------------------------------
# 2. ROLE-BASED ACCESS CONTROL
# ------------------------------------------

def check_access(role, user_id, sid, department=None):

    if role == "Admin":
        return True

    if role == "Faculty":
        return students[sid][1] == department

    if role == "Student":
        return user_id == sid

    return False


def view_result():
    role = input("Role (Admin/Faculty/Student): ")
    user_id = input("User ID: ")
    department = None

    if role == "Faculty":
        department = input("Department: ")

    sid = input("Student ID to view: ").upper()

    if sid not in students:
        print("Student not found")
        return

    if check_access(role, user_id, sid, department):
        print(decrypt(encrypted_records[sid]))
    else:
        print("ACCESS DENIED")


# ------------------------------------------
# 3. RSA DIGITAL SIGNATURE
# ------------------------------------------

def sign_and_verify():
    original = record_text("ST101")
    modified = original.replace("|85", "|95")

    signature = pkcs1_15.new(rsa_key).sign(
        SHA256.new(original.encode())
    )

    for label, message in [
        ("Original", original),
        ("Modified", modified)
    ]:
        try:
            pkcs1_15.new(rsa_key.publickey()).verify(
                SHA256.new(message.encode()),
                signature
            )
            print(label, "Signature VALID")

        except (ValueError, TypeError):
            print(label, "Signature INVALID")


# ------------------------------------------
# 4. KEY REVOCATION AND RENEWAL
# ------------------------------------------

def revoke_key():
    global key_active

    key_active = False
    print("Key revoked. Decryption disabled.")


def renew_key():
    global aes_key, key_active

    if not key_active:
        print("Old key revoked; existing data unavailable")
        return

    # Preserve records by decrypting before rotation
    plaintexts = {
        sid: decrypt(package)
        for sid, package in encrypted_records.items()
    }

    aes_key = get_random_bytes(32)

    for sid, message in plaintexts.items():
        encrypted_records[sid] = encrypt(message)

    key_active = True
    print("Key renewed and records re-encrypted")


# ------------------------------------------
# 5. HASHING
# ------------------------------------------

def hash_demo():
    original = record_text("ST101")
    modified = original.replace("|85", "|95")

    h1 = hashlib.sha256(original.encode()).hexdigest()
    h2 = hashlib.sha256(modified.encode()).hexdigest()

    print("Original hash:", h1)
    print("Modified hash:", h2)

    print("MATCH" if h1 == h2 else "MISMATCH")


# ------------------------------------------
# 6. MAIN MENU
# ------------------------------------------

def main():
    encrypt_all()

    while True:
        print("\n--- UNIVERSITY SECURITY ---")
        print("1. View Result")
        print("2. Digital Signature")
        print("3. Revoke Key")
        print("4. Renew Key")
        print("5. Hash Verification")
        print("6. Exit")

        choice = input("Choice: ")

        try:
            if choice == "1":
                view_result()

            elif choice == "2":
                sign_and_verify()

            elif choice == "3":
                revoke_key()

            elif choice == "4":
                renew_key()

            elif choice == "5":
                hash_demo()

            elif choice == "6":
                break

            else:
                print("Invalid choice")

        except (ValueError, KeyError, PermissionError) as e:
            print("Error:", e)


if __name__ == "__main__":
    main()

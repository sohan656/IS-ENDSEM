'''
report - management - record 
store the report id , department , description 
- encode the description with sha 256
- use kdf (10 rounds) , use 24 bytes for AES 192 CBC encrypt the report_id, department (make the key valid only for 120 seconds and show the expiry of the key too , shouldnt be able to use the same key once expired)
- use RSA 2048 , PKCS V1 vs 1.5 and SHA 256 to sign it and display the signature 
- make it indexable (HMAC) and also searchable based on the description key words 
- no bulk decryption once searched the keyword 
- make it role based - staff , admin
- staff had certain functions like add the record, encrypt , etc
- admin could see the records
- you need to show a audit record once the keys are tampered with , if tampered with it should show false when trying to verify signature 
- no internal department change too should be recorded
'''
import time
import json
import hmac
import hashlib
import re

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes


# ============================================================
# 1. CONFIGURATION
# ============================================================

AES_KEY_SIZE = 24       # 24 bytes for AES-192
KDF_ROUNDS = 10         # 10 iterations specified in question
KEY_LIFETIME = 120      # Key validity in seconds

PASSWORD = b"ReportManagementPassword"

reports = {}            # Stores report details
search_index = {}       # Stores HMAC tokens mapped to report IDs
audit_log = []          # Stores audit events

rsa_key = RSA.generate(2048)       # RSA-2048 key pair
search_key = get_random_bytes(32)  # Secret key for HMAC indexing


# ============================================================
# 2. AUDIT LOGGING
# ============================================================

def audit(action, report_id="", details=""):

    entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "report_id": report_id,
        "details": details
    }

    audit_log.append(entry)

    print("[AUDIT]", action, report_id, details)


def show_audit():

    print("\n========== AUDIT LOG ==========")

    if not audit_log:
        print("No audit records")
        return

    for entry in audit_log:
        print(entry)


# ============================================================
# 3. SHA-256 HASHING
# ============================================================

def hash_description(description):

    # encode() converts the string into bytes.
    # hexdigest() returns the hash as a hexadecimal string.

    return SHA256.new(
        description.encode()
    ).hexdigest()


# ============================================================
# 4. KDF - AES-192 KEY GENERATION
# ============================================================

def derive_key(salt):

    return PBKDF2(
        PASSWORD,
        salt,
        dkLen=24,              # 24 bytes required for AES-192
        count=10,              # 10 iterations specified in question
        hmac_hash_module=SHA256
    )


# ============================================================
# 5. AES-192 CBC ENCRYPTION AND DECRYPTION
# ============================================================

def aes_encrypt(message, key):

    # Creates AES cipher in CBC mode with a generated IV.
    cipher = AES.new(key, AES.MODE_CBC)

    # Converts message to bytes and pads it to AES block size.
    ciphertext = cipher.encrypt(
        pad(message.encode(), AES.block_size)
    )

    # Returns the IV and encrypted message.
    return cipher.iv, ciphertext


def aes_decrypt(iv, ciphertext, key):

    # Uses the IV saved during encryption.
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    # Decrypts ciphertext and removes padding.
    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext.decode()


# ============================================================
# 6. RSA DIGITAL SIGNATURE
# ============================================================

def sign_data(data):

    # Calculates SHA-256 of the data.
    digest = SHA256.new(data)

    # Signs the digest using RSA private key and PKCS#1 v1.5.
    return pkcs1_15.new(rsa_key).sign(digest)


def verify_signature(data, signature):

    digest = SHA256.new(data)

    try:
        # Uses RSA public key to verify the signature.
        pkcs1_15.new(
            rsa_key.publickey()
        ).verify(digest, signature)

        return True

    except (ValueError, TypeError):
        return False


# ============================================================
# 7. HMAC SEARCHABLE INDEX
# ============================================================

def keywords(description):

    # lower() converts text to lowercase.
    # re.findall() extracts individual alphanumeric words.
    # set() removes duplicate words.

    return set(
        re.findall(
            r"[a-z0-9]+",
            description.lower()
        )
    )


def make_token(word):

    # Generates an HMAC-SHA256 token for the keyword.
    return hmac.new(
        search_key,
        word.lower().encode(),
        hashlib.sha256
    ).hexdigest()


def add_to_index(report_id, description):

    for word in keywords(description):

        token = make_token(word)

        # setdefault() creates an empty set if token is absent.
        # add() inserts the report ID into that set.
        search_index.setdefault(
            token, set()
        ).add(report_id)


def search_reports(word):

    token = make_token(word.strip())

    # get() returns an empty set when no token is found.
    # sorted() returns matching IDs in sorted order.
    matches = sorted(
        search_index.get(token, set())
    )

    print("Matching report IDs:", matches)

    return matches


# ============================================================
# 8. PREPARE DATA FOR DIGITAL SIGNATURE
# ============================================================

def create_signed_data(report_id, report):

    # Collects the fields that will be signed and verified.
    data = {
        "report_id": report_id,
        "department": report["department"],
        "description_hash": hash_description(
            report["description"]
        ),
        "encrypted_id": report["encrypted_id"].hex(),
        "encrypted_dept": report["encrypted_dept"].hex(),
        "iv1": report["iv1"].hex(),
        "iv2": report["iv2"].hex(),
        "salt": report["salt"].hex(),
        "expiry": report["expiry"]
    }

    # json.dumps() converts dictionary to JSON text.
    # sort_keys=True maintains consistent key ordering.
    # encode() converts the JSON text to bytes.

    return json.dumps(
        data,
        sort_keys=True
    ).encode()


# ============================================================
# 9. ADD REPORT - STAFF
# ============================================================

def add_report():

    report_id = input("Report ID: ").strip()
    department = input("Department: ").strip()
    description = input("Description: ").strip()

    if not report_id or not department or not description:
        print("All fields are required")
        return

    if report_id in reports:
        print("Report already exists")
        return

    # Generate SHA-256 hash of description.
    description_hash = hash_description(description)

    # Generate a random 16-byte salt.
    salt = get_random_bytes(16)

    # Derive the 24-byte AES key using PBKDF2.
    key = derive_key(salt)

    # Encrypt report ID and department separately.
    iv1, encrypted_id = aes_encrypt(report_id, key)
    iv2, encrypted_dept = aes_encrypt(department, key)

    # time.time() gives current Unix timestamp in seconds.
    created = time.time()

    # Set expiry 120 seconds after key creation.
    expiry = created + KEY_LIFETIME

    reports[report_id] = {
        "department": department,
        "description": description,
        "description_hash": description_hash,
        "salt": salt,
        "iv1": iv1,
        "iv2": iv2,
        "encrypted_id": encrypted_id,
        "encrypted_dept": encrypted_dept,
        "created": created,
        "expiry": expiry,
        "key_active": True
    }

    # Convert report fields into bytes for signing.
    signed_data = create_signed_data(
        report_id,
        reports[report_id]
    )

    # Generate and store RSA signature.
    signature = sign_data(signed_data)
    reports[report_id]["signature"] = signature

    # Index description keywords using HMAC.
    add_to_index(report_id, description)

    print("\nReport created successfully")
    print("Description SHA-256:", description_hash)
    print("RSA Signature:", signature.hex())
    print("AES Key Size:", len(key), "bytes")

    # Convert expiry timestamp to readable date and time.
    print(
        "Key expires at:",
        time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(expiry)
        )
    )

    audit("REPORT_CREATED", report_id)


# ============================================================
# 10. CHECK KEY EXPIRY
# ============================================================

def check_key(report_id):

    report = reports[report_id]

    # Reject if the key was previously marked inactive.
    if not report["key_active"]:
        return False

    # Check whether the current time has passed expiry.
    if time.time() >= report["expiry"]:

        report["key_active"] = False

        audit(
            "KEY_EXPIRED",
            report_id,
            "AES key expired after 120 seconds"
        )

        return False

    return True


# ============================================================
# 11. VERIFY REPORT SIGNATURE
# ============================================================

def verify_report(report_id):

    report = reports[report_id]

    # Recreate signed bytes using current report values.
    current_data = create_signed_data(
        report_id,
        report
    )

    # Verify current data against the stored signature.
    valid = verify_signature(
        current_data,
        report["signature"]
    )

    print("Signature valid:", valid)

    if not valid:
        audit(
            "SIGNATURE_FAILED",
            report_id,
            "Report data or encryption metadata modified"
        )

    return valid


# ============================================================
# 12. VIEW INDIVIDUAL REPORT - ADMIN
# ============================================================

def view_report(report_id):

    if report_id not in reports:
        print("Report not found")
        return

    report = reports[report_id]

    # Verify signature before allowing decryption.
    if not verify_report(report_id):
        print("Integrity verification failed")
        return

    # Check whether the AES key is still valid.
    if not check_key(report_id):
        print("Key expired. Decryption denied.")
        return

    # Recreate AES key using stored salt.
    key = derive_key(report["salt"])

    # Decrypt only the selected report.
    decrypted_id = aes_decrypt(
        report["iv1"],
        report["encrypted_id"],
        key
    )

    decrypted_dept = aes_decrypt(
        report["iv2"],
        report["encrypted_dept"],
        key
    )

    print("\n========== REPORT ==========")
    print("Report ID:", decrypted_id)
    print("Department:", decrypted_dept)
    print("Description:", report["description"])
    print("Description SHA-256:", report["description_hash"])

    audit("REPORT_VIEWED", report_id)


# ============================================================
# 13. DEPARTMENT CHANGE
# ============================================================

def change_department():

    report_id = input("Report ID: ").strip()

    if report_id not in reports:
        print("Report not found")
        return

    report = reports[report_id]

    old_department = report["department"]
    new_department = input("New department: ").strip()

    if not new_department:
        print("Invalid department")
        return

    # Modify the department without updating the signature.
    report["department"] = new_department

    # Record the department change in audit log.
    audit(
        "DEPARTMENT_CHANGED",
        report_id,
        f"{old_department} -> {new_department}"
    )

    # Verify whether the original signature still matches.
    verify_report(report_id)


# ============================================================
# 14. KEY TAMPERING
# ============================================================

def tamper_key():

    report_id = input("Report ID: ").strip()

    if report_id not in reports:
        print("Report not found")
        return

    report = reports[report_id]

    # Replace the original KDF salt with a new random salt.
    report["salt"] = get_random_bytes(16)

    audit(
        "KEY_TAMPERED",
        report_id,
        "KDF salt modified"
    )

    # Verify signature after modifying the salt.
    verify_report(report_id)


# ============================================================
# 15. STAFF MENU
# ============================================================

def staff_menu():

    while True:

        print("\n========== STAFF MENU ==========")
        print("1. Add and encrypt report")
        print("2. Search report keywords")
        print("3. Back")

        choice = input("Choice: ")

        if choice == "1":
            add_report()

        elif choice == "2":
            word = input("Keyword: ")
            search_reports(word)

        elif choice == "3":
            break

        else:
            print("Invalid choice")


# ============================================================
# 16. ADMIN MENU
# ============================================================

def admin_menu():

    while True:

        print("\n========== ADMIN MENU ==========")
        print("1. Search reports")
        print("2. View individual report")
        print("3. Verify signature")
        print("4. Change department (tampering demo)")
        print("5. Tamper KDF salt (demo)")
        print("6. View audit log")
        print("7. Back")

        choice = input("Choice: ")

        try:
            if choice == "1":
                word = input("Keyword: ")
                search_reports(word)

            elif choice == "2":
                report_id = input("Report ID: ")
                view_report(report_id.strip())

            elif choice == "3":
                report_id = input("Report ID: ")
                verify_report(report_id.strip())

            elif choice == "4":
                change_department()

            elif choice == "5":
                tamper_key()

            elif choice == "6":
                show_audit()

            elif choice == "7":
                break

            else:
                print("Invalid choice")

        except (KeyError, ValueError) as e:
            print("Error:", e)


# ============================================================
# 17. MAIN MENU
# ============================================================

def main():

    while True:

        print("\n========== REPORT MANAGEMENT ==========")
        print("1. Staff")
        print("2. Admin")
        print("3. Exit")

        choice = input("Choice: ")

        if choice == "1":
            staff_menu()

        elif choice == "2":
            admin_menu()

        elif choice == "3":
            print("Exiting...")
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

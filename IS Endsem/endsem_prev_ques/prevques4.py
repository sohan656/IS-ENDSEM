'''
SECURE GRANT EXPENSE PORTAL

Scenario:

A research institute manages grant expenses through an online portal. Researchers submit grant details, reviewers check their integrity and authenticity, and the finance officer computes the total grant expenditure. The system must keep grant data confidential and verifiable, and the total must be computed without decrypting individual amounts.

Requirements:

Researcher side: The researcher enters a Grant ID, Grant Description and Grant Amount. Before storing, the system:

Encrypts the grant description with AES-192.
Encrypts the grant amount with the Paillier cryptosystem.
Computes an MD5 hash of the grant record.
Signs the hash with an RSA digital signature.
The researcher can submit grant details, and view all submitted records, including those entered earlier.

Reviewer side: The reviewer verifies the RSA signature and recomputes the MD5 hash to detect tampering. The reviewer can search the stored records by index (Grant ID) without exposing the encrypted contents. The reviewer can also view the AES-192 decrypted grant description as a hexadecimal dump.

Finance Officer side: The finance officer homomorphically aggregates the Paillier-encrypted amounts of the selected grants. The officer then verifies the signatures and decrypts only the final aggregate, never individual amounts.

Task:

Write a menu-driven Python program implementing the above roles and functions. Use role-based menus and cryptographic operations for confidentiality, integrity and authenticity. Store the encrypted, hashed and signed records persistently (file or database), so that earlier entries remain visible after a restart. Handle invalid input and tampered records gracefully. Display outputs for all functions.

Note: If the Python code is not menu-driven, the total marks obtained will be reduced to half.
'''
import os
import json
import math
import secrets
import hashlib

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import MD5
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.number import getPrime, inverse


# ==========================================================
# 1. FILES AND DATA STORAGE
# ==========================================================

DATA_FILE = "grants.json"
AES_FILE = "aes_key.bin"
RSA_FILE = "rsa_key.pem"
PAILLIER_FILE = "paillier_keys.json"

grants = {}


# ==========================================================
# 2. KEY GENERATION AND PERSISTENCE
# ==========================================================

def load_keys():
    global aes_key, rsa_key, paillier_public, paillier_private

    # Load existing AES key or create a new 24-byte key
    if os.path.exists(AES_FILE):
        with open(AES_FILE, "rb") as f:
            aes_key = f.read()
    else:
        aes_key = get_random_bytes(24)  # AES-192
        with open(AES_FILE, "wb") as f:
            f.write(aes_key)

    # Load existing RSA key or generate RSA-2048
    if os.path.exists(RSA_FILE):
        with open(RSA_FILE, "rb") as f:
            rsa_key = RSA.import_key(f.read())
    else:
        rsa_key = RSA.generate(2048)
        with open(RSA_FILE, "wb") as f:
            f.write(rsa_key.export_key())

    # Load existing Paillier keys or generate new keys
    if os.path.exists(PAILLIER_FILE):
        with open(PAILLIER_FILE, "r") as f:
            data = json.load(f)

        paillier_public = tuple(data["public"])
        paillier_private = tuple(data["private"])

    else:
        paillier_public, paillier_private = paillier_keygen()

        with open(PAILLIER_FILE, "w") as f:
            json.dump({
                "public": paillier_public,
                "private": paillier_private
            }, f)

    # Validate AES key size
    if len(aes_key) != 24:
        raise ValueError("Invalid AES-192 key size")


# ==========================================================
# 3. PAILLIER KEY GENERATION
# ==========================================================

def paillier_keygen():

    p = getPrime(512)
    q = getPrime(512)

    while p == q:
        q = getPrime(512)

    n = p * q
    ns = n * n
    g = n + 1

    lam = math.lcm(p - 1, q - 1)

    # Calculate modular inverse for Paillier decryption
    mu = inverse(lam, n)

    return (n, ns, g), (lam, mu)


# ==========================================================
# 4. PAILLIER ENCRYPTION AND DECRYPTION
# ==========================================================

def paillier_encrypt(amount):

    n, ns, g = paillier_public

    # Generate random r such that gcd(r,n)=1
    while True:
        r = secrets.randbelow(n - 1) + 1

        if math.gcd(r, n) == 1:
            break

    ciphertext = (
        pow(g, amount, ns) *
        pow(r, n, ns)
    ) % ns

    return ciphertext


def paillier_decrypt(ciphertext):

    n, ns, g = paillier_public
    lam, mu = paillier_private

    x = pow(ciphertext, lam, ns)

    # L(x) = (x-1)//n
    L = (x - 1) // n

    return (L * mu) % n


# ==========================================================
# 5. AES-192 ENCRYPTION AND DECRYPTION
# ==========================================================

def aes_encrypt(message):

    # AES.new() automatically generates a random CBC IV
    cipher = AES.new(aes_key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(message.encode(), AES.block_size)
    )

    # Store IV and ciphertext as hexadecimal strings
    return cipher.iv.hex(), ciphertext.hex()


def aes_decrypt(iv, ciphertext):

    # Convert hexadecimal strings back to bytes
    iv = bytes.fromhex(iv)
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(
        aes_key,
        AES.MODE_CBC,
        iv=iv
    )

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext.decode()


# ==========================================================
# 6. MD5 HASH AND RSA DIGITAL SIGNATURE
# ==========================================================

def record_bytes(record):

    # Select the stored fields covered by the hash/signature
    data = {
        "grant_id": record["grant_id"],
        "iv": record["iv"],
        "encrypted_description": record["encrypted_description"],
        "encrypted_amount": record["encrypted_amount"]
    }

    # sort_keys=True ensures consistent JSON field ordering
    return json.dumps(
        data,
        sort_keys=True
    ).encode()


def generate_hash(record):

    # Generate MD5 hash of the encrypted grant record
    return MD5.new(record_bytes(record)).hexdigest()


def sign_record(record):

    # Generate MD5 digest of the record
    digest = MD5.new(record_bytes(record))

    # Sign digest using RSA private key with PKCS#1 v1.5
    signature = pkcs1_15.new(rsa_key).sign(digest)

    return signature.hex()


def verify_record(record):

    try:
        # Recalculate MD5 hash using current record values
        current_hash = generate_hash(record)

        hash_valid = (
            current_hash == record["md5_hash"]
        )

        # Recalculate digest for RSA verification
        digest = MD5.new(record_bytes(record))

        signature = bytes.fromhex(
            record["signature"]
        )

        # Verify using RSA public key
        pkcs1_15.new(
            rsa_key.publickey()
        ).verify(digest, signature)

        signature_valid = True

    except (ValueError, TypeError, KeyError):
        hash_valid = False
        signature_valid = False

    return hash_valid, signature_valid


# ==========================================================
# 7. LOAD AND SAVE GRANT RECORDS
# ==========================================================

def load_grants():

    global grants

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            grants = json.load(f)

    else:
        grants = {}


def save_grants():

    # Write to a temporary file before replacing the original
    temp_file = DATA_FILE + ".tmp"

    with open(temp_file, "w") as f:
        json.dump(grants, f, indent=4)

    os.replace(temp_file, DATA_FILE)


# ==========================================================
# 8. RESEARCHER - ADD GRANT
# ==========================================================

def add_grant():

    grant_id = input("Grant ID: ").strip()
    description = input("Grant Description: ").strip()

    if not grant_id or not description:
        print("Grant ID and description are required")
        return

    if grant_id in grants:
        print("Grant ID already exists")
        return

    try:
        amount = int(input("Grant Amount: "))

        if amount < 0:
            print("Amount cannot be negative")
            return

        if amount >= paillier_public[0]:
            print("Amount exceeds Paillier range")
            return

    except ValueError:
        print("Invalid amount")
        return

    # Encrypt description using AES-192 CBC
    iv, encrypted_description = aes_encrypt(description)

    # Encrypt numerical amount using Paillier
    encrypted_amount = paillier_encrypt(amount)

    record = {
        "grant_id": grant_id,
        "iv": iv,
        "encrypted_description": encrypted_description,
        "encrypted_amount": str(encrypted_amount)
    }

    # Generate MD5 hash and RSA signature
    record["md5_hash"] = generate_hash(record)
    record["signature"] = sign_record(record)

    # Save the record in the dictionary
    grants[grant_id] = record

    # Persist the record to grants.json
    save_grants()

    print("\nGrant submitted successfully")
    print("Grant ID:", grant_id)
    print("AES Encrypted Description:", encrypted_description)
    print("Paillier Encrypted Amount:", encrypted_amount)
    print("MD5 Hash:", record["md5_hash"])
    print("RSA Signature:", record["signature"])


# ==========================================================
# 9. RESEARCHER - VIEW ALL SUBMITTED RECORDS
# ==========================================================

def view_all_grants():

    if not grants:
        print("No grant records found")
        return

    print("\n========== SUBMITTED GRANTS ==========")

    for grant_id, record in grants.items():

        print("\nGrant ID:", grant_id)

        # Display stored ciphertext, not decrypted values
        print(
            "Encrypted Description:",
            record["encrypted_description"]
        )

        print(
            "Encrypted Amount:",
            record["encrypted_amount"]
        )

        print("MD5 Hash:", record["md5_hash"])
        print("RSA Signature:", record["signature"])


# ==========================================================
# 10. REVIEWER - SEARCH BY GRANT ID
# ==========================================================

def search_grant():

    grant_id = input("Enter Grant ID: ").strip()

    # Dictionary lookup acts as the Grant ID index
    record = grants.get(grant_id)

    if record is None:
        print("Grant not found")
        return

    print("\nGrant found:", grant_id)

    # Show only the ID, without decrypting the record
    print("Matching Grant ID:", record["grant_id"])


# ==========================================================
# 11. REVIEWER - VERIFY HASH AND SIGNATURE
# ==========================================================

def reviewer_verify():

    grant_id = input("Enter Grant ID: ").strip()

    if grant_id not in grants:
        print("Grant not found")
        return

    record = grants[grant_id]

    hash_valid, signature_valid = verify_record(record)

    print("MD5 Hash Match:", hash_valid)
    print("RSA Signature Valid:", signature_valid)

    if hash_valid and signature_valid:
        print("Record integrity verified")
    else:
        print("Tampering detected")


# ==========================================================
# 12. REVIEWER - VIEW DECRYPTED DESCRIPTION AS HEX
# ==========================================================

def view_description_hex():

    grant_id = input("Enter Grant ID: ").strip()

    if grant_id not in grants:
        print("Grant not found")
        return

    record = grants[grant_id]

    hash_valid, signature_valid = verify_record(record)

    if not hash_valid or not signature_valid:
        print("Verification failed. Decryption denied.")
        return

    try:
        # Decrypt only the grant description
        description = aes_decrypt(
            record["iv"],
            record["encrypted_description"]
        )

        # Convert decrypted text to UTF-8 hexadecimal bytes
        hex_dump = description.encode().hex(" ")

        print("Grant ID:", grant_id)
        print("Decrypted Description (HEX):", hex_dump)

    except (ValueError, UnicodeError):
        print("Decryption failed")


# ==========================================================
# 13. FINANCE - HOMOMORPHIC TOTAL
# ==========================================================

def calculate_total():

    if not grants:
        print("No grants available")
        return

    print("\nAvailable Grant IDs:")
    print(", ".join(grants.keys()))

    selected = input(
        "Enter Grant IDs separated by commas: "
    ).strip()

    # Split input into individual IDs
    selected_ids = [
        gid.strip()
        for gid in selected.split(",")
        if gid.strip()
    ]

    if not selected_ids:
        print("No grants selected")
        return

    # Remove duplicate IDs without changing order
    selected_ids = list(dict.fromkeys(selected_ids))

    # Verify all selected records before aggregation
    for grant_id in selected_ids:

        if grant_id not in grants:
            print("Invalid Grant ID:", grant_id)
            return

        record = grants[grant_id]

        hash_valid, signature_valid = verify_record(record)

        print(
            grant_id,
            "Hash:", hash_valid,
            "Signature:", signature_valid
        )

        if not hash_valid or not signature_valid:
            print("Tampered record detected. Total cancelled.")
            return

    n, ns, g = paillier_public

    # Multiplicative identity for encrypted aggregation
    encrypted_total = 1

    for grant_id in selected_ids:

        # Read only the encrypted amount
        ciphertext = int(
            grants[grant_id]["encrypted_amount"]
        )

        if not (1 <= ciphertext < ns):
            print("Invalid Paillier ciphertext")
            return

        # Multiply encrypted values modulo n²
        encrypted_total = (
            encrypted_total * ciphertext
        ) % ns

    # Decrypt only the final aggregate
    total = paillier_decrypt(encrypted_total)

    print("\nSelected Grants:", selected_ids)
    print("Encrypted Aggregate:", encrypted_total)
    print("Final Total Grant Expenditure:", total)


# ==========================================================
# 14. TAMPERING DEMONSTRATION
# ==========================================================

def tamper_grant():

    grant_id = input("Grant ID to tamper: ").strip()

    if grant_id not in grants:
        print("Grant not found")
        return

    record = grants[grant_id]

    # Change encrypted description without updating hash/signature
    ciphertext = bytearray.fromhex(
        record["encrypted_description"]
    )

    if not ciphertext:
        print("Empty ciphertext")
        return

    ciphertext[0] ^= 1

    record["encrypted_description"] = ciphertext.hex()

    save_grants()

    print("Encrypted record modified")

    hash_valid, signature_valid = verify_record(record)

    print("MD5 Hash Match:", hash_valid)
    print("RSA Signature Valid:", signature_valid)


# ==========================================================
# 15. RESEARCHER MENU
# ==========================================================

def researcher_menu():

    while True:
        print("\n========== RESEARCHER ==========")
        print("1. Submit Grant")
        print("2. View All Submitted Records")
        print("3. Back")

        choice = input("Choice: ")

        if choice == "1":
            add_grant()

        elif choice == "2":
            view_all_grants()

        elif choice == "3":
            break

        else:
            print("Invalid choice")


# ==========================================================
# 16. REVIEWER MENU
# ==========================================================

def reviewer_menu():

    while True:
        print("\n========== REVIEWER ==========")
        print("1. Search Grant by ID")
        print("2. Verify MD5 and RSA Signature")
        print("3. View Decrypted Description (HEX)")
        print("4. Back")

        choice = input("Choice: ")

        if choice == "1":
            search_grant()

        elif choice == "2":
            reviewer_verify()

        elif choice == "3":
            view_description_hex()

        elif choice == "4":
            break

        else:
            print("Invalid choice")


# ==========================================================
# 17. FINANCE OFFICER MENU
# ==========================================================

def finance_menu():

    while True:
        print("\n========== FINANCE OFFICER ==========")
        print("1. Calculate Total Grant Expenditure")
        print("2. Back")

        choice = input("Choice: ")

        if choice == "1":
            calculate_total()

        elif choice == "2":
            break

        else:
            print("Invalid choice")


# ==========================================================
# 18. MAIN MENU
# ==========================================================

def main():

    # Load cryptographic keys and earlier grant records
    load_keys()
    load_grants()

    while True:
        print("\n========== SECURE GRANT PORTAL ==========")
        print("1. Researcher")
        print("2. Reviewer")
        print("3. Finance Officer")
        print("4. Tamper Record (Demo)")
        print("5. Exit")

        choice = input("Choice: ")

        try:
            if choice == "1":
                researcher_menu()

            elif choice == "2":
                reviewer_menu()

            elif choice == "3":
                finance_menu()

            elif choice == "4":
                tamper_grant()

            elif choice == "5":
                print("Exiting...")
                break

            else:
                print("Invalid choice")

        except (ValueError, KeyError, TypeError) as e:
            print("Operation failed:", e)


if __name__ == "__main__":
    main()

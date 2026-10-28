import json
import base64
import hashlib
import hmac
import math
import secrets
from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.number import getPrime, inverse
from Cryptodome.Util.Padding import pad, unpad


# --------------------------------------------------
# 1. FIXED SHIPMENT DATA
# --------------------------------------------------

records = {
    "S201": ["Asha", "Mysuru", 12000, "Dispatched"],
    "S202": ["Kiran", "Udupi", 8500, "In Transit"],
    "S203": ["Naveen", "Mangaluru", 17500, "Dispatched"],
    "S204": ["Divya", "Mysuru", 6400, "Delivered"]
}

# Generate keys for this application session
aes_key = get_random_bytes(32)
search_key = get_random_bytes(32)
rsa_key = RSA.generate(2048)

encrypted_records = {}
search_index = {}

FILE_ORIGINAL = "shipment_records.txt"
FILE_ENCRYPTED = "encrypted_shipment_records.txt"


# --------------------------------------------------
# 2. RECORD FORMATTING
# --------------------------------------------------

def record_text(sid):
    r = records[sid]
    return f"{sid}|{r[0]}|{r[1]}|{r[2]}|{r[3]}"


def display_records():
    print("\n--- Shipment Records ---")

    for sid in records:
        print(record_text(sid))


# --------------------------------------------------
# 3. AES ENCRYPTION AND DECRYPTION
# --------------------------------------------------

def aes_encrypt(message):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(
        pad(message.encode(), AES.block_size)
    )

    return base64.b64encode(
        cipher.iv + ciphertext
    ).decode()


def aes_decrypt(encoded):
    raw = base64.b64decode(encoded)

    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext.decode()


# --------------------------------------------------
# 4. SEARCHABLE ENCRYPTED INDEX
# --------------------------------------------------

def make_token(word):
    return hmac.new(
        search_key,
        word.lower().encode(),
        hashlib.sha256
    ).hexdigest()


def build_index():
    search_index.clear()
    encrypted_records.clear()

    for sid, data in records.items():

        # Encrypt each complete record
        encrypted_records[sid] = aes_encrypt(
            record_text(sid)
        )

        # Index all fields as searchable terms
        words = [sid, data[0], data[1], data[3]]

        for word in words:
            token = make_token(str(word))
            search_index.setdefault(token, set()).add(sid)


def search_records():
    keyword = input("Enter search keyword: ").strip()

    if not keyword:
        print("Invalid keyword")
        return

    token = make_token(keyword)
    matches = sorted(search_index.get(token, set()))

    if matches:
        print("Matching shipment IDs:", ", ".join(matches))
    else:
        print("No matching records")


def retrieve_record():
    keyword = input("Enter search keyword: ").strip()

    token = make_token(keyword)
    matches = sorted(search_index.get(token, set()))

    if not matches:
        print("No matching records")
        return

    print("Matching IDs:", ", ".join(matches))

    sid = input("Enter shipment ID to decrypt: ").strip().upper()

    if sid not in matches:
        print("Invalid selection")
        return

    password = input("Enter authorization password: ")

    if password != "admin123":
        print("Access denied")
        return

    print("Decrypted record:")
    print(aes_decrypt(encrypted_records[sid]))


# --------------------------------------------------
# 5. PAILLIER HOMOMORPHIC ENCRYPTION
# --------------------------------------------------

def paillier_keygen():
    p = getPrime(256)
    q = getPrime(256)

    while p == q:
        q = getPrime(256)

    n = p * q
    nsquare = n * n
    g = n + 1

    lam = math.lcm(p - 1, q - 1)

    x = pow(g, lam, nsquare)
    L = (x - 1) // n
    mu = inverse(L, n)

    return (n, nsquare, g), (lam, mu)


def paillier_encrypt(m, public):
    n, nsquare, g = public

    r = secrets.randbelow(n - 1) + 1

    while math.gcd(r, n) != 1:
        r = secrets.randbelow(n - 1) + 1

    return (
        pow(g, m, nsquare) *
        pow(r, n, nsquare)
    ) % nsquare


def paillier_decrypt(c, public, private):
    n, nsquare, g = public
    lam, mu = private

    x = pow(c, lam, nsquare)
    L = (x - 1) // n

    return (L * mu) % n


def homomorphic_total():
    public, private = paillier_keygen()

    values = [r[2] for r in records.values()]

    encrypted_values = [
        paillier_encrypt(value, public)
        for value in values
    ]

    n, nsquare, g = public

    # Ciphertext multiplication = plaintext addition
    encrypted_sum = 1

    for c in encrypted_values:
        encrypted_sum = (
            encrypted_sum * c
        ) % nsquare

    # Decrypt only the final aggregate
    total = paillier_decrypt(
        encrypted_sum, public, private
    )

    print("\nEncrypted individual values:")
    for c in encrypted_values:
        print(c)

    print("\nEncrypted aggregate:", encrypted_sum)
    print("Total declared value = Rs.", total)


# --------------------------------------------------
# 6. RSA DIGITAL SIGNATURE
# --------------------------------------------------

def digital_signature():
    original = record_text("S201")

    # Hash original message
    original_hash = SHA256.new(original.encode())

    # Sign using private key
    signature = pkcs1_15.new(rsa_key).sign(
        original_hash
    )

    public_key = rsa_key.publickey()

    print("\nOriginal:", original)

    # Verify original message
    try:
        pkcs1_15.new(public_key).verify(
            SHA256.new(original.encode()),
            signature
        )
        print("Original message: Signature VALID")

    except (ValueError, TypeError):
        print("Original message: Signature INVALID")
        
def modified_signature():
    original = record_text("S201")
    modified = original.replace("12000", "12001")

    # Hash modified message
    modified_hash = SHA256.new(modified.encode())

    # Sign using private key
    signature = pkcs1_15.new(rsa_key).sign(
        modified_hash
    )

    public_key = rsa_key.publickey()

    print("\nModified:", modified)

    # Verify modified message
    try:
        pkcs1_15.new(public_key).verify(
            SHA256.new(modified.encode()),
            signature
        )
        print("Modified message: Signature VALID")

    except (ValueError, TypeError):
        print("Modified message: Signature INVALID")


# --------------------------------------------------
# 7. FILE HANDLING AND AES ENCRYPTION
# --------------------------------------------------

def save_encrypted_records():

    # Save original records
    with open(FILE_ORIGINAL, "w") as f:
        for sid in records:
            f.write(record_text(sid) + "\n")

    # Encrypt and save each record
    with open(FILE_ENCRYPTED, "w") as f:
        for sid in records:
            encrypted = aes_encrypt(record_text(sid))
            f.write(sid + "|" + encrypted + "\n")

    print("Original records saved in:", FILE_ORIGINAL)
    print("Encrypted records saved in:", FILE_ENCRYPTED)

    password = input("Enter password to decrypt: ")

    if password != "admin123":
        print("Access denied")
        return

    print("\nDecrypted records:")

    with open(FILE_ENCRYPTED, "r") as f:
        for line in f:
            sid, ciphertext = line.strip().split("|", 1)

            plaintext = aes_decrypt(ciphertext)
            print(plaintext)


# --------------------------------------------------
# 8. SHA-256 HASH AND INTEGRITY CHECK
# --------------------------------------------------

def integrity_check():
    original = record_text("S201")

    # Encrypt and decrypt the original record
    encrypted = aes_encrypt(original)
    decrypted = aes_decrypt(encrypted)

    original_hash = hashlib.sha256(
        original.encode()
    ).hexdigest()

    decrypted_hash = hashlib.sha256(
        decrypted.encode()
    ).hexdigest()

    print("\nOriginal record:", original)
    print("Decrypted record:", decrypted)

    if original_hash == decrypted_hash:
        print("HASH MATCH")
    else:
        print("HASH MISMATCH")

def modify_hash():
    original = record_text("S201")
    encrypted = aes_encrypt(original)
    decrypted = aes_decrypt(encrypted)
    modified = decrypted.replace("12000", "12001")
    modified_hash = hashlib.sha256(
        modified.encode()
    ).hexdigest()
    original_hash = hashlib.sha256(
            original.encode()
        ).hexdigest()
    
    decrypted_hash = hashlib.sha256(
        decrypted.encode()
    ).hexdigest()
    print("\nModified record:", modified)
    
    if original_hash == modified_hash:
        print("HASH MATCH")
    else:
        print("HASH MISMATCH")


# --------------------------------------------------
# 9. MAIN MENU
# --------------------------------------------------

def main():

    build_index()

    while True:
        print("\n========== SECURETRANSIT ==========")
        print("1. Load / Display Records")
        print("2. Search Records")
        print("3. Retrieve / Decrypt Record")
        print("4. Homomorphic Total")
        print("5. Generate / Verify Signature")
        print("6. Encrypt / Save Records")
        print("7. Hash / Integrity Check")
        print("8. Exit")

        choice = input("Enter choice: ").strip()

        try:
            if choice == "1":
                display_records()

            elif choice == "2":
                search_records()

            elif choice == "3":
                retrieve_record()

            elif choice == "4":
                homomorphic_total()

            elif choice == "5":
                digital_signature()

            elif choice == "6":
                save_encrypted_records()

            elif choice == "7":
                integrity_check()
                modify_hash()

            elif choice == "8":
                print("Exiting SecureTransit...")
                break

            else:
                print("Invalid menu choice. Try again.")

        except Exception as e:
            print("Operation failed:", e)


if __name__ == "__main__":
    main()

'''
Question 1: Secure Hospital Management System
20 marks
A hospital named MediSecure wants to develop a secure patient management system. The hospital stores confidential patient records containing patient ID, name, disease, medical bill and doctor.

The following records are provided:
ID	    Name	Disease	     Bill (₹)	Doctor
P101	Rahul	Diabetes	 12,000	    Sharma
P102	Asha	Fever	     8,500	    Kumar
P103	Kiran	Diabetes	 17,500	    Sharma
P104	Divya	Asthma	     6,400	    Rao

Requirements:
1. Searchable Encryption (3 marks): Encrypt patient records using AES and create a searchable index. Searching for Diabetes must return P101 and P103 without decrypting all records.
2. Homomorphic Encryption (4 marks): Use Paillier encryption to calculate the total medical bill without decrypting individual bills.
3. Digital Signature (3 marks): Sign patient P101's record using RSA and verify it. Modify the bill and demonstrate signature verification failure.
4. File Encryption and Hashing (3 marks): Save encrypted patient records to a file. Decrypt a selected record and compare its SHA-256 hash with the original.
5. Integration (2 marks): Implement a menu-driven application with error handling.
6. Documentation (5 marks): Explain the algorithms, outputs and security properties.
'''



import hashlib
import hmac
import math
import secrets
import json

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.number import getPrime, inverse


patients = {
    "P101": ["Rahul", "Diabetes", 12000, "Sharma"],
    "P102": ["Asha", "Fever", 8500, "Kumar"],
    "P103": ["Kiran", "Diabetes", 17500, "Sharma"],
    "P104": ["Divya", "Asthma", 6400, "Rao"]
}

aes_key = get_random_bytes(16)
index_key = get_random_bytes(32)
rsa_key = RSA.generate(2048)

encrypted_records = {}
search_index = {}


# AES-GCM encryption

def encrypt_record(message):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, ciphertext, tag


def decrypt_record(package):
    nonce, ciphertext, tag = package
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


def patient_text(pid):
    p = patients[pid]
    return f"{pid}|{p[0]}|{p[1]}|{p[2]}|{p[3]}"


# Searchable index

def token(word):
    return hmac.new(
        index_key, word.lower().encode(), hashlib.sha256
    ).hexdigest()


def build_index():
    search_index.clear()
    encrypted_records.clear()

    for pid, data in patients.items():
        encrypted_records[pid] = encrypt_record(patient_text(pid))

        for word in [pid, data[0], data[1], data[3]]:
            search_index.setdefault(token(str(word)), set()).add(pid)


def search_patient(keyword):
    return sorted(search_index.get(token(keyword), set()))


# Paillier encryption

def paillier_keys():
    p, q = getPrime(256), getPrime(256)
    while p == q:
        q = getPrime(256)

    n = p * q
    ns = n * n
    lam = math.lcm(p - 1, q - 1)
    mu = inverse(lam, n)

    return (n, ns), (lam, mu)


def paillier_encrypt(m, public):
    n, ns = public
    r = secrets.randbelow(n - 1) + 1

    while math.gcd(r, n) != 1:
        r = secrets.randbelow(n - 1) + 1

    return (pow(n + 1, m, ns) * pow(r, n, ns)) % ns


def paillier_decrypt(c, public, private):
    n, ns = public
    lam, mu = private

    x = pow(c, lam, ns)
    return (((x - 1) // n) * mu) % n


def total_bills():
    public, private = paillier_keys()
    n, ns = public

    encrypted_bills = [
        paillier_encrypt(p[2], public)
        for p in patients.values()
    ]

    encrypted_total = 1
    for c in encrypted_bills:
        encrypted_total = (encrypted_total * c) % ns

    return paillier_decrypt(encrypted_total, public, private)


# RSA digital signature

def signature_demo():
    original = patient_text("P101")
    modified = original.replace("12000", "15000")

    signature = pkcs1_15.new(rsa_key).sign(
        SHA256.new(original.encode())
    )

    for label, message in [
        ("Original", original),
        ("Modified", modified)
    ]:
        try:
            pkcs1_15.new(rsa_key.publickey()).verify(
                SHA256.new(message.encode()), signature
            )
            print(label, ": VALID")
        except (ValueError, TypeError):
            print(label, ": INVALID")


# Encrypted file storage

def save_file():
    output = {}

    for pid, package in encrypted_records.items():
        output[pid] = [part.hex() for part in package]

    with open("patients_encrypted.json", "w") as f:
        json.dump(output, f, indent=2)

    print("Encrypted records saved")


# SHA-256 integrity

def integrity_demo():
    original = patient_text("P101")
    recovered = decrypt_record(encrypted_records["P101"])

    h1 = hashlib.sha256(original.encode()).hexdigest()
    h2 = hashlib.sha256(recovered.encode()).hexdigest()

    print("Integrity:", "MATCH" if h1 == h2 else "MISMATCH")


# Menu

def main():
    build_index()

    while True:
        print("\n1. Display patient IDs")
        print("2. Search encrypted records")
        print("3. Decrypt patient record")
        print("4. Total medical bills")
        print("5. Digital signature")
        print("6. Save encrypted file")
        print("7. Integrity verification")
        print("8. Exit")

        choice = input("Choice: ")

        try:
            if choice == "1":
                print(list(patients.keys()))

            elif choice == "2":
                word = input("Search: ")
                print(search_patient(word))

            elif choice == "3":
                pid = input("Patient ID: ").upper()
                print(decrypt_record(encrypted_records[pid]))

            elif choice == "4":
                print("Total bills: Rs.", total_bills())

            elif choice == "5":
                signature_demo()

            elif choice == "6":
                save_file()

            elif choice == "7":
                integrity_demo()

            elif choice == "8":
                break

            else:
                print("Invalid choice")

        except (KeyError, ValueError) as e:
            print("Error:", e)


if __name__ == "__main__":
    main()

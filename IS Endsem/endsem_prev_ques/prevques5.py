'''
Create 2 files
Patient_records and encrypted_patient_records

A dataset was provided so put that data into the patient records

Patient_id
Patient_name
Diagnosis
Blood_glucose 
Treatment

A menu driven program

1) display the dataset
2) encrypt the dataset using AES (any byte)
3) produce a sha-256 of a given record using its pateint id
4) sign the dataset using RSA
5) verify the signature for tampering
6) add the total blood glucose of all patients and show the homomorphic sum using pallier
7) search for patient using diagnosis and dipaly the patient is
8) display the patient records for a user input patient id only after verification and decrypt the data
9) exit 
'''
import os
import json
import math
import hmac
import hashlib
import secrets

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.number import getPrime, inverse


# ==================================================
# 1. DATASET AND FILES
# ==================================================

PATIENT_FILE = "patient_records.txt"
ENCRYPTED_FILE = "encrypted_patient_records.txt"

# Replace these sample records with your given dataset
patients = {
    "P101": ["Rahul", "Diabetes", 180, "Insulin"],
    "P102": ["Asha", "Fever", 95, "Paracetamol"],
    "P103": ["Kiran", "Diabetes", 210, "Metformin"],
    "P104": ["Divya", "Hypertension", 120, "Medication"],
    "P105": ["Naveen", "Diabetes", 160, "Insulin"]
}

# AES-256 key: 32 bytes
aes_key = get_random_bytes(32)

# RSA-2048 key pair
rsa_key = RSA.generate(2048)

# Separate key for HMAC search tokens
search_key = get_random_bytes(32)

# Stores encrypted records in memory
encrypted_records = {}

# Maps diagnosis tokens to patient IDs
search_index = {}

# Stores the signature of the complete dataset
dataset_signature = None


# ==================================================
# 2. RECORD FORMATTING
# ==================================================

def record_text(pid):

    p = patients[pid]

    return f"{pid}|{p[0]}|{p[1]}|{p[2]}|{p[3]}"


def dataset_text():

    # Sort IDs to keep record order consistent
    return "\n".join(
        record_text(pid)
        for pid in sorted(patients)
    )


# ==================================================
# 3. CREATE ORIGINAL PATIENT FILE
# ==================================================

def save_patient_file():

    # Write all patient records to plaintext file
    with open(PATIENT_FILE, "w") as f:

        f.write(
            "Patient_ID|Patient_Name|Diagnosis|Blood_Glucose|Treatment\n"
        )

        for pid in sorted(patients):
            f.write(record_text(pid) + "\n")


# ==================================================
# 4. DISPLAY DATASET
# ==================================================

def display_dataset():

    print("\n========== PATIENT DATASET ==========")

    print(
        f"{'ID':<8}{'Name':<12}"
        f"{'Diagnosis':<18}"
        f"{'Glucose':<10}{'Treatment'}"
    )

    print("-" * 65)

    for pid, p in patients.items():

        print(
            f"{pid:<8}{p[0]:<12}"
            f"{p[1]:<18}"
            f"{p[2]:<10}{p[3]}"
        )


# ==================================================
# 5. AES-256 CBC ENCRYPTION
# ==================================================

def aes_encrypt(message):

    cipher = AES.new(aes_key, AES.MODE_CBC)

    # Convert text to bytes and add padding
    ciphertext = cipher.encrypt(
        pad(message.encode(), AES.block_size)
    )

    return cipher.iv, ciphertext


def aes_decrypt(iv, ciphertext):

    cipher = AES.new(
        aes_key,
        AES.MODE_CBC,
        iv=iv
    )

    # Decrypt and remove padding
    return unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    ).decode()


# ==================================================
# 6. ENCRYPT DATASET AND SAVE TO FILE
# ==================================================

def encrypt_dataset():

    encrypted_records.clear()

    with open(ENCRYPTED_FILE, "w") as f:

        for pid in sorted(patients):

            plaintext = record_text(pid)

            iv, ciphertext = aes_encrypt(plaintext)

            # Store IV and ciphertext as hexadecimal strings
            encrypted_records[pid] = {
                "iv": iv.hex(),
                "ciphertext": ciphertext.hex()
            }

            # Save each encrypted record as JSON
            f.write(
                json.dumps({
                    "patient_id": pid,
                    "iv": iv.hex(),
                    "ciphertext": ciphertext.hex()
                }) + "\n"
            )

    print("\nDataset encrypted successfully")
    print("Encrypted file:", ENCRYPTED_FILE)

    for pid, record in encrypted_records.items():
        print(pid, ":", record["ciphertext"])


# ==================================================
# 7. SHA-256 HASH OF SELECTED RECORD
# ==================================================

def hash_record():

    pid = input("Enter Patient ID: ").strip().upper()

    if pid not in patients:
        print("Patient not found")
        return

    message = record_text(pid)

    # Generate SHA-256 hexadecimal digest
    digest = SHA256.new(
        message.encode()
    ).hexdigest()

    print("Patient ID:", pid)
    print("SHA-256:", digest)


# ==================================================
# 8. RSA DIGITAL SIGNATURE OF DATASET
# ==================================================

def sign_dataset():

    global dataset_signature

    # Generate SHA-256 hash of complete dataset
    digest = SHA256.new(
        dataset_text().encode()
    )

    # Sign using RSA private key
    dataset_signature = pkcs1_15.new(
        rsa_key
    ).sign(digest)

    print("\nDataset signed successfully")
    print("RSA Signature:", dataset_signature.hex())


# ==================================================
# 9. VERIFY RSA SIGNATURE
# ==================================================

def verify_dataset():

    if dataset_signature is None:
        print("Dataset has not been signed")
        return False

    # Recalculate hash of current dataset
    digest = SHA256.new(
        dataset_text().encode()
    )

    try:
        # Verify using RSA public key
        pkcs1_15.new(
            rsa_key.publickey()
        ).verify(
            digest,
            dataset_signature
        )

        print("Signature valid: True")
        return True

    except (ValueError, TypeError):

        print("Signature valid: False")
        print("Dataset tampering detected")
        return False


# ==================================================
# 10. PAILLIER KEY GENERATION
# ==================================================

def paillier_keygen():

    p = getPrime(256)
    q = getPrime(256)

    while p == q:
        q = getPrime(256)

    n = p * q
    ns = n * n
    g = n + 1

    lam = math.lcm(p - 1, q - 1)

    # Calculate modular inverse
    mu = inverse(lam, n)

    return (n, ns, g), (lam, mu)


# ==================================================
# 11. PAILLIER ENCRYPTION AND DECRYPTION
# ==================================================

def paillier_encrypt(m, public):

    n, ns, g = public

    # Generate random r coprime to n
    while True:

        r = secrets.randbelow(n - 1) + 1

        if math.gcd(r, n) == 1:
            break

    return (
        pow(g, m, ns) *
        pow(r, n, ns)
    ) % ns


def paillier_decrypt(c, public, private):

    n, ns, g = public
    lam, mu = private

    x = pow(c, lam, ns)

    # L(x) = (x - 1) // n
    L = (x - 1) // n

    return (L * mu) % n


# ==================================================
# 12. HOMOMORPHIC SUM OF BLOOD GLUCOSE
# ==================================================

def homomorphic_sum():

    public, private = paillier_keygen()

    n, ns, g = public

    # Extract blood glucose values
    glucose_values = [
        p[2] for p in patients.values()
    ]

    # Encrypt each glucose value
    encrypted_values = [
        paillier_encrypt(value, public)
        for value in glucose_values
    ]

    # Multiply ciphertexts modulo n²
    encrypted_total = 1

    for ciphertext in encrypted_values:

        encrypted_total = (
            encrypted_total * ciphertext
        ) % ns

    # Decrypt only the final aggregate
    total = paillier_decrypt(
        encrypted_total,
        public,
        private
    )

    print("\nEncrypted glucose values:")

    for value in encrypted_values:
        print(value)

    print("\nEncrypted Homomorphic Sum:", encrypted_total)
    print("Decrypted Total Blood Glucose:", total)


# ==================================================
# 13. HMAC SEARCHABLE INDEX
# ==================================================

def make_token(word):

    return hmac.new(
        search_key,
        word.lower().encode(),
        hashlib.sha256
    ).hexdigest()


def build_index():

    search_index.clear()

    for pid, p in patients.items():

        diagnosis = p[1]

        # Create token for diagnosis
        token = make_token(diagnosis)

        search_index.setdefault(
            token, set()
        ).add(pid)


# ==================================================
# 14. SEARCH PATIENT USING DIAGNOSIS
# ==================================================

def search_patient():

    diagnosis = input(
        "Enter Diagnosis: "
    ).strip()

    token = make_token(diagnosis)

    matches = sorted(
        search_index.get(token, set())
    )

    if matches:
        print("Matching Patient IDs:", matches)

    else:
        print("No matching patients")


# ==================================================
# 15. LOAD ENCRYPTED RECORDS FROM FILE
# ==================================================

def load_encrypted_records():

    encrypted_records.clear()

    if not os.path.exists(ENCRYPTED_FILE):
        return

    with open(ENCRYPTED_FILE, "r") as f:

        for line in f:

            record = json.loads(line)

            encrypted_records[
                record["patient_id"]
            ] = {
                "iv": record["iv"],
                "ciphertext": record["ciphertext"]
            }


# ==================================================
# 16. VERIFY AND DECRYPT SELECTED PATIENT
# ==================================================

def view_patient():

    pid = input("Enter Patient ID: ").strip().upper()

    if pid not in patients:
        print("Patient not found")
        return

    # Verify dataset signature before decryption
    if not verify_dataset():
        print("Access denied: Verification failed")
        return

    if pid not in encrypted_records:
        print("Please encrypt the dataset first")
        return

    record = encrypted_records[pid]

    try:
        # Convert hexadecimal IV and ciphertext to bytes
        iv = bytes.fromhex(record["iv"])
        ciphertext = bytes.fromhex(record["ciphertext"])

        # Decrypt only selected patient record
        plaintext = aes_decrypt(iv, ciphertext)

        # Compare decrypted record with original
        if plaintext != record_text(pid):
            print("Record mismatch detected")
            return

        print("\nDecrypted Patient Record:")
        print(plaintext)

    except (ValueError, UnicodeError):
        print("Decryption failed or record tampered")


# ==================================================
# 17. MAIN MENU
# ==================================================

def main():

    save_patient_file()
    build_index()
    load_encrypted_records()

    while True:

        print("\n========== PATIENT RECORD MANAGEMENT ==========")
        print("1. Display Dataset")
        print("2. Encrypt Dataset using AES")
        print("3. SHA-256 of Patient Record")
        print("4. Sign Dataset using RSA")
        print("5. Verify Signature")
        print("6. Homomorphic Blood Glucose Sum")
        print("7. Search Patient by Diagnosis")
        print("8. Verify and Decrypt Patient Record")
        print("9. Exit")

        choice = input("Enter choice: ").strip()

        try:
            if choice == "1":
                display_dataset()

            elif choice == "2":
                encrypt_dataset()

            elif choice == "3":
                hash_record()

            elif choice == "4":
                sign_dataset()

            elif choice == "5":
                verify_dataset()

            elif choice == "6":
                homomorphic_sum()

            elif choice == "7":
                search_patient()

            elif choice == "8":
                view_patient()

            elif choice == "9":
                print("Exiting...")
                break

            else:
                print("Invalid choice")

        except (ValueError, KeyError, TypeError) as e:
            print("Error:", e)


if __name__ == "__main__":
    main()

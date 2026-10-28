'''
A hospital network consists of three hospitals (H1, H2, H3) and a central research server. Each hospital maintains confidential patient records containing patient IDs, diagnoses, medical reports, and treatment costs.

The hospitals need to exchange patient information securely while allowing the research server to perform statistical analysis without accessing individual patient records.

Develop a menu-driven Python application that satisfies the following requirements:

Part A — Secure Communication

When Hospital H1 sends a patient record to H2:
- Generate RSA key pairs for both hospitals.
- Establish a shared secret using Diffie–Hellman key exchange.
- Encrypt the patient record using AES with a key derived from the shared secret.
- Generate a SHA-256 hash of the record.
- Digitally sign the record using H1's private key.
- At H2, decrypt the record and verify the digital signature before accepting it.
Part B — Encrypted Medical Statistics

Three hospitals report their total treatment costs:
Hospital	Treatment cost
H1	₹15,000
H2	₹25,000
H3	₹35,000
- Use Paillier encryption to encrypt each hospital's treatment cost.
- Calculate the total cost without decrypting individual values.
- Decrypt the final result and verify it is ₹75,000.
Part C — Searchable Medical Records

The hospital database contains at least 10 encrypted patient records.
- Implement searchable encryption using AES and a secure keyword index.
- Allow authorized doctors to search records using keywords such as "diabetes" or "cardiac".
- Display only matching records after authorization and decryption.
Part D — Access Control and Key Management
- Doctors can access patient records.
- Researchers can access only aggregated statistics.
- Unauthorized users cannot decrypt patient records.
- Implement RSA key revocation for compromised hospital keys.
Part E — Security Testing

Demonstrate what happens when:
- A patient record is modified after signing.
- An unauthorized researcher attempts to decrypt a patient record.
- A hospital attempts communication using a revoked key.
- A valid doctor searches for an encrypted patient record.
'''

"""Educational hospital cryptography demonstration using pycryptodomex.
Not a production medical records system.
"""

# Standard libraries: hashing, keyed hashes, JSON formatting, mathematics, text parsing, and secure randomness.
import hashlib
import hmac
import json
import math
import re
import secrets
from dataclasses import dataclass

# PyCryptodomeX imports use Cryptodome (NOT Crypto).
# AES encrypts records; RSA signs exchange messages; SHA256 hashes signed data.
# getPrime and inverse support Paillier key generation and decryption.
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util.number import getPrime, inverse


# Encode dictionaries consistently: identical records always produce identical bytes.
# This matters because signatures and hashes operate on bytes, not Python dictionaries.

# ========================================================================
# DATA SERIALIZATION
# ========================================================================
def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


# AES-GCM provides confidentiality AND an authentication tag.
# AAD (additional authenticated data) is checked but not encrypted.

# ========================================================================
# AES ENCRYPTION AND DECRYPTION
# ========================================================================
def aes_encrypt(key, data, aad=b''):
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {'nonce': cipher.nonce.hex(), 'ciphertext': ciphertext.hex(), 'tag': tag.hex()}


# Decrypt and verify the GCM tag; modified ciphertext or AAD raises ValueError.

def aes_decrypt(key, package, aad=b''):
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(package['nonce']))
    cipher.update(aad)
    return cipher.decrypt_and_verify(bytes.fromhex(package['ciphertext']), bytes.fromhex(package['tag']))


# Each hospital has a name, its RSA private key (public key can be derived),
# and an active flag used to simulate key revocation.

# ========================================================================
# HOSPITAL MODEL
# ========================================================================
@dataclass


class Hospital:
    name: str
    rsa_key: object
    active: bool = True


# Paillier is additively homomorphic: E(a) * E(b) mod n^2 = E(a+b).
# Only the holder of the Paillier private key can decrypt the final sum.

# ========================================================================
# PAILLIER HOMOMORPHIC ENCRYPTION
# ========================================================================
class Paillier:

    def __init__(self, bits=1024):

        # Choose two distinct random primes and build the Paillier public modulus n.
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        while p == q:
            q = getPrime(bits // 2)
        self.n = p * q
        self.n2 = self.n * self.n
        self.g = self.n + 1

        # lambda and mu form the private decryption key.
        self.lam = math.lcm(p - 1, q - 1)
        u = pow(self.g, self.lam, self.n2)
        self.mu = inverse((u - 1) // self.n, self.n)

    # Encrypt a nonnegative integer with fresh randomness r each time.

    def encrypt(self, value):
        if not 0 <= value < self.n:
            raise ValueError('Paillier plaintext must be in [0, n).')
        r = secrets.randbelow(self.n - 1) + 1
        while math.gcd(r, self.n) != 1:
            r = secrets.randbelow(self.n - 1) + 1
        return (pow(self.g, value, self.n2) * pow(r, self.n, self.n2)) % self.n2

    # Multiply ciphertexts to add their underlying plaintext values.

    def add(self, a, b):
        return a * b % self.n2

    # Recover the plaintext using the Paillier private parameters.

    def decrypt(self, ciphertext):
        u = pow(ciphertext, self.lam, self.n2)
        return (((u - 1) // self.n) * self.mu) % self.n


# Coordinates users, patient records, encrypted storage, key exchange, and access control.

# ========================================================================
# HOSPITAL APPLICATION
# ========================================================================
class HospitalSystem:

    def __init__(self):

        # Each hospital gets its own 2048-bit RSA key pair.
        self.hospitals = {name: Hospital(name, RSA.generate(2048)) for name in ('H1', 'H2', 'H3')}

        # Demo-only role mapping (not a real login/authentication system).
        self.roles = {'doctor1': 'doctor', 'doctor2': 'doctor', 'researcher1': 'researcher'}

        # Ten sample patient records used for encryption and keyword search.
        self.records = {
            'P001': {'patient_id': 'P001', 'diagnosis': 'diabetes', 'notes': 'routine checkup'},
            'P002': {'patient_id': 'P002', 'diagnosis': 'cardiac', 'notes': 'heart monitoring'},
            'P003': {'patient_id': 'P003', 'diagnosis': 'asthma', 'notes': 'inhaler prescribed'},
            'P004': {'patient_id': 'P004', 'diagnosis': 'diabetes', 'notes': 'blood sugar test'},
            'P005': {'patient_id': 'P005', 'diagnosis': 'fracture', 'notes': 'bone healing'},
            'P006': {'patient_id': 'P006', 'diagnosis': 'cardiac', 'notes': 'follow up'},
            'P007': {'patient_id': 'P007', 'diagnosis': 'fever', 'notes': 'rest advised'},
            'P008': {'patient_id': 'P008', 'diagnosis': 'allergy', 'notes': 'skin rash'},
            'P009': {'patient_id': 'P009', 'diagnosis': 'diabetes', 'notes': 'diet consultation'},
            'P010': {'patient_id': 'P010', 'diagnosis': 'migraine', 'notes': 'headache treatment'},
        }

        # Separate AES key for stored records and HMAC key for search tokens.
        self.data_key = get_random_bytes(32)
        self.index_key = get_random_bytes(32)
        self.encrypted_records = {}
        self.search_index = {}
        self.build_encrypted_database()
        self.paillier = None

    # Role-based access control: doctors search records, researchers request totals.

    def authorize(self, username, role):
        return self.roles.get(username) == role

    # Encrypt every patient record and build an inverted index of keyword -> record IDs.
    # Instead of storing plaintext keywords, index keys are deterministic HMAC-SHA256 tokens.
    # This is a teaching example of SSE; repeated searches can still leak access patterns.

    def build_encrypted_database(self):
        self.encrypted_records.clear()
        self.search_index.clear()
        for record_id, record in self.records.items():
            self.encrypted_records[record_id] = aes_encrypt(self.data_key, canonical(record), record_id.encode())

            # Extract distinct lowercase words from the record fields.
            words = set(re.findall(r'[a-z0-9]+', ' '.join(str(x) for x in record.values()).lower()))
            for word in words:

                # Same keyword + secret index key yields the same search token.
                token = hmac.new(self.index_key, word.encode(), hashlib.sha256).hexdigest()
                self.search_index.setdefault(token, []).append(record_id)

    # Authorize the doctor, derive a search token, find IDs, then decrypt matches.

    def search(self, username, keyword):
        if not self.authorize(username, 'doctor'):
            raise PermissionError('Access denied: only doctors can search patient records.')
        words = re.findall(r'[a-z0-9]+', keyword.lower())
        if len(words) != 1:
            raise ValueError('Enter exactly one keyword.')
        token = hmac.new(self.index_key, words[0].encode(), hashlib.sha256).hexdigest()
        ids = self.search_index.get(token, [])
        return [json.loads(aes_decrypt(self.data_key, self.encrypted_records[rid], rid.encode())) for rid in ids]

    # End-to-end demo: authenticate DH exchange, derive AES key, sign and encrypt
    # a record, then decrypt and verify it at the receiving hospital.

    def send_record(self, source, destination, patient_id, tamper=False):
        if source not in self.hospitals or destination not in self.hospitals:
            raise ValueError('Unknown hospital.')
        sender = self.hospitals[source]
        receiver = self.hospitals[destination]
        if not sender.active or not receiver.active:
            raise PermissionError('Rejected: a hospital RSA key is revoked.')
        if patient_id not in self.records:
            raise ValueError('Unknown patient ID.')

        # Ephemeral finite-field DH, with signed exchange transcript.
        # For lab demonstration only: production should use a vetted authenticated key-exchange protocol.
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08

        # Small illustrative group; do not use for real security.
        g = 2

        # a and b are private DH exponents; A and B are public DH values.
        a = secrets.randbelow(p - 3) + 2
        b = secrets.randbelow(p - 3) + 2
        A = pow(g, a, p)
        B = pow(g, b, p)

        # Bind the public DH values and hospital names into a signed transcript.
        # Signatures help prevent an attacker substituting DH values.
        transcript = canonical({'from': source, 'to': destination, 'A': A, 'B': B})
        sig_sender = pkcs1_15.new(sender.rsa_key).sign(SHA256.new(transcript))
        sig_receiver = pkcs1_15.new(receiver.rsa_key).sign(SHA256.new(transcript))
        pkcs1_15.new(sender.rsa_key.publickey()).verify(SHA256.new(transcript), sig_sender)
        pkcs1_15.new(receiver.rsa_key.publickey()).verify(SHA256.new(transcript), sig_receiver)

        # Both parties independently calculate g^(a*b) mod p.
        shared_sender = pow(B, a, p)
        shared_receiver = pow(A, b, p)
        assert shared_sender == shared_receiver

        # Demonstration-only derivation; a production system should use HKDF.
        session_key = hashlib.sha256(shared_sender.to_bytes((p.bit_length() + 7) // 8, 'big') + transcript).digest()

        # Hash the plaintext, sign it with sender RSA private key, then AES-encrypt it.
        message = canonical(self.records[patient_id])
        digest = hashlib.sha256(message).hexdigest()
        signature = pkcs1_15.new(sender.rsa_key).sign(SHA256.new(message))
        encrypted = aes_encrypt(session_key, message, transcript)

        # Receiver checks the AES-GCM tag while decrypting.
        received = aes_decrypt(session_key, encrypted, transcript)

        # Optional exam test: modify the decrypted message AFTER the original signature.
        # This simulates tampering and should cause hash/signature checks to fail.
        if tamper:
            modified = json.loads(received)
            modified['notes'] = 'TAMPERED'
            received = canonical(modified)

        # Compare SHA-256 values and verify the signature with sender public key.
        integrity_ok = hmac.compare_digest(hashlib.sha256(received).hexdigest(), digest)
        try:
            pkcs1_15.new(sender.rsa_key.publickey()).verify(SHA256.new(received), signature)
            signature_ok = True
        except (ValueError, TypeError):
            signature_ok = False
        return {'dh_shared_secret_matches': shared_sender == shared_receiver,
                'sha256_integrity': integrity_ok, 'signature_valid': signature_ok,
                'accepted': integrity_ok and signature_ok,
                'received_record': json.loads(received) if integrity_ok and signature_ok else None}

    # Mark an RSA identity key as revoked; subsequent send_record calls reject it.

    def revoke(self, hospital):
        if hospital not in self.hospitals:
            raise ValueError('Unknown hospital.')
        self.hospitals[hospital].active = False

    # Replace the RSA key pair and reactivate the hospital.

    def renew(self, hospital):
        if hospital not in self.hospitals:
            raise ValueError('Unknown hospital.')
        self.hospitals[hospital] = Hospital(hospital, RSA.generate(2048))

    # Encrypt each hospital cost, add ciphertexts, and decrypt ONLY the aggregate.

    def encrypted_total(self, username, amounts):
        if not self.authorize(username, 'researcher'):
            raise PermissionError('Only researchers can request aggregate statistics.')
        if not amounts or any(x < 0 for x in amounts):
            raise ValueError('Provide nonnegative deposit amounts.')
        if self.paillier is None:
            self.paillier = Paillier()
        encrypted = [self.paillier.encrypt(x) for x in amounts]

        # 1 is the multiplicative identity; fold ciphertexts by modular multiplication.
        combined = 1
        for value in encrypted:
            combined = self.paillier.add(combined, value)
        return {'encrypted_individual_values': encrypted,
                'encrypted_total': combined,
                'decrypted_total': self.paillier.decrypt(combined),
                'expected_total': sum(amounts)}


# Command-line menu: run individual lab concepts and security test cases.

# ========================================================================
# INTERACTIVE MENU
# ========================================================================
def main():
    system = HospitalSystem()
    while True:
        print('\n=== SECURE HOSPITAL SYSTEM ===')
        print('1. Send encrypted patient record')
        print('2. Test transaction tampering')
        print('3. Calculate encrypted treatment total')
        print('4. Search encrypted patient records')
        print('5. Revoke hospital key')
        print('6. Renew hospital key')
        print('7. Test unauthorized search')
        print('8. Show public key status')
        print('0. Exit')
        choice = input('Choose: ').strip()

        # Catch expected input/authorization errors without terminating the menu.
        try:
            if choice in ('1', '2'):
                source = input('Source hospital (H1/H2/H3): ').strip().upper()
                destination = input('Destination hospital (H1/H2/H3): ').strip().upper()
                patient = input('Patient ID (P001-P010): ').strip().upper()
                print(json.dumps(system.send_record(source, destination, patient, tamper=(choice == '2')), indent=2))
            elif choice == '3':
                username = input('Username (researcher1): ').strip()
                result = system.encrypted_total(username, [15000, 25000, 35000])
                print('Encrypted individual amounts:', result['encrypted_individual_values'])
                print('Encrypted total:', result['encrypted_total'])
                print('Decrypted total:', result['decrypted_total'])
                print('Expected total:', result['expected_total'])
            elif choice == '4':
                username = input('Username (doctor1/doctor2): ').strip()
                keyword = input('Keyword: ').strip()
                print(json.dumps(system.search(username, keyword), indent=2))
            elif choice == '5':
                hospital = input('Hospital: ').strip().upper()
                system.revoke(hospital)
                print('Key revoked. New communications using it will be rejected.')
            elif choice == '6':
                hospital = input('Hospital: ').strip().upper()
                system.renew(hospital)
                print('New RSA key pair generated; hospital is active.')
            elif choice == '7':
                print(system.search('researcher1', 'diabetes'))
            elif choice == '8':
                for hospital in system.hospitals.values():
                    print(hospital.name, 'ACTIVE' if hospital.active else 'REVOKED',
                          'RSA bits:', hospital.rsa_key.size_in_bits())
            elif choice == '0':
                break
            else:
                print('Invalid option.')
        except (ValueError, PermissionError, KeyError) as exc:
            print('Error:', exc)


if __name__ == '__main__':
    main()

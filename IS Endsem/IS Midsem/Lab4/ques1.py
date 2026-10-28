'''
import os
from dataclasses import dataclass
from typing import Dict

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.number import getPrime, GCD


# ============================================================
# Key Management System
# ============================================================

@dataclass
class KeyRecord:
    name: str
    private_key: RSA.RsaKey
    public_key: RSA.RsaKey
    revoked: bool = False


class KeyManagementSystem:
    """
    Centralized Key Management System.

    Responsibilities:
        - Generate RSA keys
        - Register subsystems
        - Distribute public keys
        - Revoke keys
        - Check key status
    """

    def __init__(self):
        self.keys: Dict[str, KeyRecord] = {}

    def register_subsystem(self, name):
        if name in self.keys:
            raise ValueError(f"{name} is already registered.")

        private_key = RSA.generate(3072)

        self.keys[name] = KeyRecord(
            name=name,
            private_key=private_key,
            public_key=private_key.publickey()
        )

        print(f"[KMS] Registered: {name}")

    def get_private_key(self, name):
        if name not in self.keys:
            raise ValueError("Unknown subsystem.")

        if self.keys[name].revoked:
            raise PermissionError(
                f"Key for {name} has been revoked."
            )

        return self.keys[name].private_key

    def get_public_key(self, name):
        if name not in self.keys:
            raise ValueError("Unknown subsystem.")

        if self.keys[name].revoked:
            raise PermissionError(
                f"Key for {name} has been revoked."
            )

        return self.keys[name].public_key

    def revoke_key(self, name):
        if name not in self.keys:
            raise ValueError("Unknown subsystem.")

        self.keys[name].revoked = True
        print(f"[KMS] Key revoked: {name}")

    def restore_key(self, name):
        if name not in self.keys:
            raise ValueError("Unknown subsystem.")

        self.keys[name].revoked = False
        print(f"[KMS] Key restored: {name}")

    def is_trusted(self, name):
        return (
            name in self.keys
            and not self.keys[name].revoked
        )

    def list_subsystems(self):
        return list(self.keys.keys())


# ============================================================
# Diffie-Hellman Parameters
# ============================================================

class DHParameters:
    """
    Demonstration DH parameters.

    p is a 2048-bit prime.
    g = 2.
    """

    def __init__(self):
        self.p = getPrime(2048)
        self.g = 2


class DHKeyPair:

    def __init__(self, params):
        self.params = params

        # Private DH value
        self.private = int.from_bytes(
            get_random_bytes(32),
            "big"
        )

        # Ensure 1 < private < p
        self.private = (
            self.private % (params.p - 2)
        ) + 2

        # Public DH value
        self.public = pow(
            params.g,
            self.private,
            params.p
        )


def derive_session_key(private_key, peer_public_key, p):
    """
    Calculate DH shared secret and derive a 256-bit
    AES key using HKDF.
    """

    shared_secret = pow(
        peer_public_key,
        private_key,
        p
    )

    shared_secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8,
        "big"
    )

    return HKDF(
        master=shared_secret_bytes,
        key_len=32,
        salt=None,
        hashmod=SHA256,
        context=b"SecureCorp-DH-AES-Session"
    )


# ============================================================
# Secure Document
# ============================================================

@dataclass
class SecureDocument:
    sender: str
    receiver: str

    dh_public_key: int

    nonce: bytes
    ciphertext: bytes
    tag: bytes

    encrypted_session_key: bytes
    signature: bytes


# ============================================================
# Secure Subsystem
# ============================================================

class SecureSubsystem:

    def __init__(self, name, kms, dh_params):
        self.name = name
        self.kms = kms
        self.dh_params = dh_params

        # Register with centralized KMS
        self.kms.register_subsystem(name)

    # --------------------------------------------------------
    # RSA Digital Signature
    # --------------------------------------------------------

    def sign(self, data):
        private_key = self.kms.get_private_key(self.name)

        digest = SHA256.new(data)

        signature = pss.new(private_key).sign(digest)

        return signature

    def verify_signature(
        self,
        sender,
        data,
        signature
    ):
        public_key = self.kms.get_public_key(sender)

        digest = SHA256.new(data)

        try:
            pss.new(public_key).verify(
                digest,
                signature
            )
            return True

        except (ValueError, TypeError):
            return False

    # --------------------------------------------------------
    # Create DH Key Pair
    # --------------------------------------------------------

    def create_dh_keypair(self):
        return DHKeyPair(self.dh_params)

    # --------------------------------------------------------
    # Encrypt Document
    # --------------------------------------------------------

    def encrypt_document(
        self,
        receiver,
        document
    ):

        # Check sender and receiver
        if not self.kms.is_trusted(self.name):
            raise PermissionError(
                f"{self.name} is not trusted."
            )

        if not self.kms.is_trusted(receiver):
            raise PermissionError(
                f"{receiver} is not trusted."
            )

        # ----------------------------------------------------
        # 1. Generate ephemeral DH keys
        # ----------------------------------------------------

        sender_dh = self.create_dh_keypair()

        # In a real implementation, the receiver would
        # provide its ephemeral DH public key during the
        # authenticated handshake.

        receiver_dh = self.create_dh_keypair()

        # ----------------------------------------------------
        # 2. Calculate DH shared secret
        # ----------------------------------------------------

        session_key = derive_session_key(
            sender_dh.private,
            receiver_dh.public,
            self.dh_params.p
        )

        # ----------------------------------------------------
        # 3. Encrypt document with AES-GCM
        # ----------------------------------------------------

        nonce = get_random_bytes(12)

        aes = AES.new(
            session_key,
            AES.MODE_GCM,
            nonce=nonce
        )

        ciphertext, tag = aes.encrypt_and_digest(
            document
        )

        # ----------------------------------------------------
        # 4. Protect session key with RSA
        # ----------------------------------------------------

        receiver_public_key = (
            self.kms.get_public_key(receiver)
        )

        rsa_cipher = PKCS1_OAEP.new(
            receiver_public_key,
            hashAlgo=SHA256
        )

        encrypted_session_key = rsa_cipher.encrypt(
            session_key
        )

        # ----------------------------------------------------
        # 5. Digital signature
        # ----------------------------------------------------

        dh_public_bytes = str(
            sender_dh.public
        ).encode()

        data_to_sign = (
            self.name.encode()
            + receiver.encode()
            + dh_public_bytes
            + nonce
            + ciphertext
            + tag
        )

        signature = self.sign(data_to_sign)

        return SecureDocument(
            sender=self.name,
            receiver=receiver,
            dh_public_key=sender_dh.public,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            encrypted_session_key=encrypted_session_key,
            signature=signature
        )

    # --------------------------------------------------------
    # Decrypt Document
    # --------------------------------------------------------

    def decrypt_document(self, secure_document):

        sender = secure_document.sender

        # ----------------------------------------------------
        # Check trust status
        # ----------------------------------------------------

        if not self.kms.is_trusted(sender):
            raise PermissionError(
                f"Sender {sender} is revoked or unknown."
            )

        if not self.kms.is_trusted(self.name):
            raise PermissionError(
                f"Receiver {self.name} is revoked."
            )

        if secure_document.receiver != self.name:
            raise PermissionError(
                "This document is not intended for this system."
            )

        # ----------------------------------------------------
        # Verify digital signature
        # ----------------------------------------------------

        data_to_verify = (
            sender.encode()
            + self.name.encode()
            + str(
                secure_document.dh_public_key
            ).encode()
            + secure_document.nonce
            + secure_document.ciphertext
            + secure_document.tag
        )

        valid = self.verify_signature(
            sender,
            data_to_verify,
            secure_document.signature
        )

        if not valid:
            raise ValueError(
                "Digital signature verification failed."
            )

        print(
            f"[{self.name}] "
            "Digital signature verified."
        )

        # ----------------------------------------------------
        # Recover AES session key using RSA
        # ----------------------------------------------------

        private_key = (
            self.kms.get_private_key(self.name)
        )

        rsa_cipher = PKCS1_OAEP.new(
            private_key,
            hashAlgo=SHA256
        )

        session_key = rsa_cipher.decrypt(
            secure_document.encrypted_session_key
        )

        # ----------------------------------------------------
        # Decrypt using AES-GCM
        # ----------------------------------------------------

        aes = AES.new(
            session_key,
            AES.MODE_GCM,
            nonce=secure_document.nonce
        )

        plaintext = aes.decrypt_and_verify(
            secure_document.ciphertext,
            secure_document.tag
        )

        return plaintext


# ============================================================
# Main Program
# ============================================================

def main():

    print("=" * 70)
    print("SECURECORP SECURE COMMUNICATION SYSTEM")
    print("=" * 70)

    # --------------------------------------------------------
    # Create Key Management System
    # --------------------------------------------------------

    kms = KeyManagementSystem()

    # --------------------------------------------------------
    # Create DH parameters
    # --------------------------------------------------------

    dh_params = DHParameters()

    # --------------------------------------------------------
    # Create enterprise subsystems
    # --------------------------------------------------------

    finance = SecureSubsystem(
        "Finance System (System A)",
        kms,
        dh_params
    )

    hr = SecureSubsystem(
        "HR System (System B)",
        kms,
        dh_params
    )

    supply_chain = SecureSubsystem(
        "Supply Chain System (System C)",
        kms,
        dh_params
    )

    # --------------------------------------------------------
    # Display registered systems
    # --------------------------------------------------------

    print("\nRegistered subsystems:")

    for system in kms.list_subsystems():
        print("  -", system)

    # ========================================================
    # Finance -> HR
    # ========================================================

    print("\n" + "-" * 70)
    print("FINANCE -> HR")
    print("-" * 70)

    financial_report = (
        b"CONFIDENTIAL FINANCIAL REPORT\n"
        b"Revenue: $25,000,000\n"
        b"Profit: $6,200,000\n"
        b"Fiscal Year: 2026\n"
    )

    secure_report = finance.encrypt_document(
        "HR System (System B)",
        financial_report
    )

    decrypted_report = hr.decrypt_document(
        secure_report
    )

    print("\n[HR] Decrypted document:")
    print(decrypted_report.decode())

    # ========================================================
    # HR -> Supply Chain
    # ========================================================

    print("\n" + "-" * 70)
    print("HR -> SUPPLY CHAIN")
    print("-" * 70)

    employee_contract = (
        b"EMPLOYEE CONTRACT\n"
        b"Employee ID: EMP-1001\n"
        b"Department: Supply Chain\n"
        b"Employment Status: Active\n"
    )

    secure_contract = hr.encrypt_document(
        "Supply Chain System (System C)",
        employee_contract
    )

    decrypted_contract = (
        supply_chain.decrypt_document(
            secure_contract
        )
    )

    print("\n[Supply Chain] Decrypted document:")
    print(decrypted_contract.decode())

    # ========================================================
    # Supply Chain -> Finance
    # ========================================================

    print("\n" + "-" * 70)
    print("SUPPLY CHAIN -> FINANCE")
    print("-" * 70)

    procurement_order = (
        b"PROCUREMENT ORDER\n"
        b"Order ID: PO-5001\n"
        b"Item: Industrial Equipment\n"
        b"Quantity: 50\n"
    )

    secure_order = supply_chain.encrypt_document(
        "Finance System (System A)",
        procurement_order
    )

    decrypted_order = finance.decrypt_document(
        secure_order
    )

    print("\n[Finance] Decrypted document:")
    print(decrypted_order.decode())

    # ========================================================
    # KEY REVOCATION
    # ========================================================

    print("\n" + "-" * 70)
    print("KEY REVOCATION TEST")
    print("-" * 70)

    kms.revoke_key(
        "HR System (System B)"
    )

    print(
        "HR trusted status:",
        kms.is_trusted(
            "HR System (System B)"
        )
    )

    try:
        finance.encrypt_document(
            "HR System (System B)",
            b"Confidential data"
        )

    except PermissionError as e:
        print("[SECURITY] Communication blocked.")
        print("[SECURITY]", e)

    # ========================================================
    # ADD NEW SUBSYSTEM
    # ========================================================

    print("\n" + "-" * 70)
    print("SCALABILITY TEST")
    print("-" * 70)

    analytics = SecureSubsystem(
        "Analytics System (System D)",
        kms,
        dh_params
    )

    print(
        f"\nNew subsystem added: {analytics.name}"
    )

    print("\nUpdated subsystem list:")

    for system in kms.list_subsystems():
        print("  -", system)


if __name__ == "__main__":
    main()




'''
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.number import getPrime


# ---------- RSA KEY GENERATION ----------

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()


# ---------- DIFFIE-HELLMAN ----------

def diffie_hellman():
    p = getPrime(1024)
    g = 2

    # System A private/public keys
    a = 12345
    A = pow(g, a, p)

    # System B private/public keys
    b = 67890
    B = pow(g, b, p)

    # Shared secret
    secret_A = pow(B, a, p)
    secret_B = pow(A, b, p)

    assert secret_A == secret_B

    # Convert shared secret into AES key
    secret_bytes = secret_A.to_bytes(
        (secret_A.bit_length() + 7) // 8,
        "big"
    )

    aes_key = HKDF(
        secret_bytes,
        32,
        salt=None,
        hashmod=SHA256
    )

    return aes_key


# ---------- AES ENCRYPTION ----------

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(
        message.encode()
    )

    return cipher.nonce, ciphertext, tag


# ---------- AES DECRYPTION ----------

def decrypt_message(key, nonce, ciphertext, tag):
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext.decode()


# ---------- MAIN ----------

print("SECURECORP COMMUNICATION")

# RSA keys
finance_private, finance_public = generate_rsa_keys()
hr_private, hr_public = generate_rsa_keys()

print("\nRSA keys generated.")

# Diffie-Hellman
session_key = diffie_hellman()

print("Diffie-Hellman shared key established.")

# Encrypt
message = "Confidential financial report"

nonce, ciphertext, tag = encrypt_message(
    session_key,
    message
)

print("\nEncrypted message:", ciphertext.hex())

# Decrypt
decrypted = decrypt_message(
    session_key,
    nonce,
    ciphertext,
    tag
)

print("Decrypted message:", decrypted)


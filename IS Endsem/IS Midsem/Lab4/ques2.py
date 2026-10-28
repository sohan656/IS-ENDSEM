'''
import os
import json
import base64
import secrets
from datetime import datetime, timedelta

from Cryptodome.Random import getPrime
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import PBKDF2


# ============================================================
# SECURE STORAGE
# ============================================================

class SecureKeyStorage:
    """
    Provides encrypted storage for private keys.

    In a production healthcare environment, an HSM or
    enterprise KMS would normally be preferred.
    """

    def __init__(self, storage_file="secure_keys.json"):
        self.storage_file = storage_file

        # In a real system this key must NOT be hard-coded.
        # It would be protected by an HSM or secret manager.
        self.master_key = SHA256.new(
            b"SecureHealthcareMasterKey"
        ).digest()

    def encrypt_data(self, data):
        """
        Encrypt data using AES-GCM.
        """

        cipher = AES.new(
            self.master_key,
            AES.MODE_GCM
        )

        ciphertext, tag = cipher.encrypt_and_digest(
            data.encode()
        )

        return {
            "nonce": base64.b64encode(
                cipher.nonce
            ).decode(),

            "ciphertext": base64.b64encode(
                ciphertext
            ).decode(),

            "tag": base64.b64encode(
                tag
            ).decode()
        }

    def decrypt_data(self, encrypted_data):
        """
        Decrypt AES-GCM protected data.
        """

        nonce = base64.b64decode(
            encrypted_data["nonce"]
        )

        ciphertext = base64.b64decode(
            encrypted_data["ciphertext"]
        )

        tag = base64.b64decode(
            encrypted_data["tag"]
        )

        cipher = AES.new(
            self.master_key,
            AES.MODE_GCM,
            nonce=nonce
        )

        plaintext = cipher.decrypt_and_verify(
            ciphertext,
            tag
        )

        return plaintext.decode()

    def save(self, data):
        """
        Save encrypted key data to disk.
        """

        with open(
            self.storage_file,
            "w"
        ) as file:

            json.dump(
                data,
                file,
                indent=4
            )

    def load(self):
        """
        Load key data from disk.
        """

        if not os.path.exists(
            self.storage_file
        ):
            return {}

        with open(
            self.storage_file,
            "r"
        ) as file:

            return json.load(file)


# ============================================================
# AUDIT LOGGER
# ============================================================

class AuditLogger:

    def __init__(self, log_file="audit.log"):
        self.log_file = log_file

    def log(
        self,
        operation,
        facility,
        status="SUCCESS",
        details=""
    ):

        timestamp = datetime.now().isoformat()

        entry = (
            f"{timestamp} | "
            f"Operation={operation} | "
            f"Facility={facility} | "
            f"Status={status} | "
            f"Details={details}\n"
        )

        with open(
            self.log_file,
            "a"
        ) as file:

            file.write(entry)

        print(
            "[AUDIT]",
            entry.strip()
        )


# ============================================================
# RABIN CRYPTOSYSTEM
# ============================================================

class RabinCryptosystem:

    def __init__(self, key_size=1024):

        self.key_size = key_size

    # --------------------------------------------------------
    # Generate Rabin Keys
    # --------------------------------------------------------

    def generate_keys(self):

        half_size = self.key_size // 2

        # Rabin requires primes p and q such that
        # p ≡ 3 (mod 4) and q ≡ 3 (mod 4)

        while True:

            p = getPrime(half_size)

            if p % 4 == 3:
                break

        while True:

            q = getPrime(half_size)

            if q % 4 == 3 and q != p:
                break

        # Public key
        n = p * q

        # Private key
        private_key = {
            "p": p,
            "q": q
        }

        public_key = {
            "n": n
        }

        return public_key, private_key

    # --------------------------------------------------------
    # Rabin Encryption
    # --------------------------------------------------------

    def encrypt(
        self,
        message,
        public_key
    ):

        n = public_key["n"]

        # Convert plaintext to integer
        message_bytes = message.encode()

        m = int.from_bytes(
            message_bytes,
            "big"
        )

        if m >= n:
            raise ValueError(
                "Message is too large for this Rabin key."
            )

        # Rabin encryption:
        #
        # c = m² mod n

        ciphertext = pow(
            m,
            2,
            n
        )

        return ciphertext

    # --------------------------------------------------------
    # Extended Euclidean Algorithm
    # --------------------------------------------------------

    @staticmethod
    def extended_gcd(a, b):

        if b == 0:
            return 1, 0, a

        x1, y1, gcd = (
            RabinCryptosystem.extended_gcd(
                b,
                a % b
            )
        )

        x = y1
        y = x1 - (a // b) * y1

        return x, y, gcd

    # --------------------------------------------------------
    # Modular Inverse
    # --------------------------------------------------------

    @staticmethod
    def mod_inverse(a, m):

        x, y, gcd = (
            RabinCryptosystem.extended_gcd(
                a,
                m
            )
        )

        if gcd != 1:
            raise ValueError(
                "Modular inverse does not exist."
            )

        return x % m

    # --------------------------------------------------------
    # Rabin Decryption
    # --------------------------------------------------------

    def decrypt(
        self,
        ciphertext,
        private_key
    ):

        p = private_key["p"]
        q = private_key["q"]

        n = p * q

        # ----------------------------------------------------
        # Calculate square roots modulo p and q
        # ----------------------------------------------------

        mp = pow(
            ciphertext,
            (p + 1) // 4,
            p
        )

        mq = pow(
            ciphertext,
            (q + 1) // 4,
            q
        )

        # ----------------------------------------------------
        # Chinese Remainder Theorem
        # ----------------------------------------------------

        yp = self.mod_inverse(
            p,
            q
        )

        yq = self.mod_inverse(
            q,
            p
        )

        r1 = (
            yp * p * mq
            + yq * q * mp
        ) % n

        r2 = n - r1

        r3 = (
            yp * p * mq
            - yq * q * mp
        ) % n

        r4 = n - r3

        roots = [
            r1,
            r2,
            r3,
            r4
        ]

        # ----------------------------------------------------
        # Try all four possible plaintext roots
        # ----------------------------------------------------

        for root in roots:

            try:

                length = (
                    (root.bit_length() + 7) // 8
                )

                message = root.to_bytes(
                    length,
                    "big"
                ).decode()

                return message

            except (
                UnicodeDecodeError,
                ValueError
            ):
                continue

        raise ValueError(
            "Could not determine the correct plaintext."
        )


# ============================================================
# FACILITY RECORD
# ============================================================

class Facility:

    def __init__(
        self,
        facility_id,
        name,
        facility_type
    ):

        self.facility_id = facility_id
        self.name = name
        self.facility_type = facility_type

        self.active = True
        self.key_version = 1

        self.created = datetime.now()
        self.expires = (
            datetime.now()
            + timedelta(days=365)
        )


# ============================================================
# CENTRALIZED KEY MANAGEMENT SERVICE
# ============================================================

class HealthcareKMS:

    def __init__(
        self,
        key_size=1024,
        storage_file="secure_keys.json"
    ):

        self.key_size = key_size

        self.rabin = RabinCryptosystem(
            key_size
        )

        self.storage = SecureKeyStorage(
            storage_file
        )

        self.logger = AuditLogger()

        self.facilities = {}

        # Load previously stored keys
        self.load_keys()

    # --------------------------------------------------------
    # Register Facility
    # --------------------------------------------------------

    def register_facility(
        self,
        facility_id,
        name,
        facility_type
    ):

        if facility_id in self.facilities:

            raise ValueError(
                "Facility already registered."
            )

        facility = Facility(
            facility_id,
            name,
            facility_type
        )

        self.facilities[
            facility_id
        ] = facility

        self.generate_keys(
            facility_id
        )

        self.logger.log(
            "FACILITY_REGISTERED",
            facility_id,
            details=name
        )

    # --------------------------------------------------------
    # Generate Keys
    # --------------------------------------------------------

    def generate_keys(
        self,
        facility_id
    ):

        public_key, private_key = (
            self.rabin.generate_keys()
        )

        facility = self.facilities[
            facility_id
        ]

        # Encrypt private key before storage
        private_key_string = json.dumps(
            private_key
        )

        encrypted_private_key = (
            self.storage.encrypt_data(
                private_key_string
            )
        )

        # Store public and encrypted private keys
        key_record = {

            "public_key": public_key,

            "private_key": encrypted_private_key,

            "version": facility.key_version,

            "created": str(
                datetime.now()
            ),

            "expires": str(
                datetime.now()
                + timedelta(days=365)
            )
        }

        # Save to facility object
        facility.keys = key_record

        self.save_keys()

        self.logger.log(
            "KEY_GENERATED",
            facility_id,
            details=f"Version {facility.key_version}"
        )

    # --------------------------------------------------------
    # Save All Keys
    # --------------------------------------------------------

    def save_keys(self):

        data = {}

        for facility_id, facility in (
            self.facilities.items()
        ):

            if hasattr(
                facility,
                "keys"
            ):

                data[
                    facility_id
                ] = {

                    "name": facility.name,

                    "type": facility.facility_type,

                    "active": facility.active,

                    "key_version":
                        facility.key_version,

                    "created":
                        str(facility.created),

                    "expires":
                        str(facility.expires),

                    "keys":
                        facility.keys
                }

        self.storage.save(
            data
        )

    # --------------------------------------------------------
    # Load Keys
    # --------------------------------------------------------

    def load_keys(self):

        data = self.storage.load()

        for facility_id, record in (
            data.items()
        ):

            facility = Facility(
                facility_id,
                record["name"],
                record["type"]
            )

            facility.active = (
                record["active"]
            )

            facility.key_version = (
                record["key_version"]
            )

            facility.keys = (
                record["keys"]
            )

            self.facilities[
                facility_id
            ] = facility

    # --------------------------------------------------------
    # Key Distribution
    # --------------------------------------------------------

    def distribute_keys(
        self,
        facility_id
    ):

        if facility_id not in self.facilities:

            raise ValueError(
                "Facility not registered."
            )

        facility = self.facilities[
            facility_id
        ]

        # Check whether facility is active
        if not facility.active:

            self.logger.log(
                "KEY_DISTRIBUTION",
                facility_id,
                "FAILED",
                "Facility inactive"
            )

            raise PermissionError(
                "Facility is inactive."
            )

        # Get encrypted private key
        encrypted_private = (
            facility.keys[
                "private_key"
            ]
        )

        # Decrypt it only for authorized distribution
        private_string = (
            self.storage.decrypt_data(
                encrypted_private
            )
        )

        private_key = json.loads(
            private_string
        )

        public_key = (
            facility.keys[
                "public_key"
            ]
        )

        self.logger.log(
            "KEY_DISTRIBUTION",
            facility_id,
            details=(
                f"Version "
                f"{facility.key_version}"
            )
        )

        return (
            public_key,
            private_key
        )

    # --------------------------------------------------------
    # Revoke Key
    # --------------------------------------------------------

    def revoke_key(
        self,
        facility_id,
        reason="Not specified"
    ):

        if facility_id not in self.facilities:

            raise ValueError(
                "Facility not found."
            )

        facility = self.facilities[
            facility_id
        ]

        facility.active = False

        self.save_keys()

        self.logger.log(
            "KEY_REVOKED",
            facility_id,
            details=reason
        )

    # --------------------------------------------------------
    # Renew Key
    # --------------------------------------------------------

    def renew_key(
        self,
        facility_id
    ):

        if facility_id not in self.facilities:

            raise ValueError(
                "Facility not found."
            )

        facility = self.facilities[
            facility_id
        ]

        # Increase key version
        facility.key_version += 1

        # Generate new keys
        self.generate_keys(
            facility_id
        )

        # Update expiration date
        facility.expires = (
            datetime.now()
            + timedelta(days=365)
        )

        # Reactivate facility
        facility.active = True

        self.save_keys()

        self.logger.log(
            "KEY_RENEWED",
            facility_id,
            details=(
                f"New version "
                f"{facility.key_version}"
            )
        )

    # --------------------------------------------------------
    # Automatic Key Renewal
    # --------------------------------------------------------

    def automatic_renewal(self):

        current_time = datetime.now()

        for facility_id, facility in (
            self.facilities.items()
        ):

            if current_time >= facility.expires:

                self.renew_key(
                    facility_id
                )

                self.logger.log(
                    "AUTOMATIC_RENEWAL",
                    facility_id
                )

    # --------------------------------------------------------
    # Display Facility Information
    # --------------------------------------------------------

    def show_facilities(self):

        print(
            "\nREGISTERED FACILITIES"
        )

        for facility_id, facility in (
            self.facilities.items()
        ):

            status = (
                "ACTIVE"
                if facility.active
                else "REVOKED"
            )

            print(
                f"{facility_id} | "
                f"{facility.name} | "
                f"{facility.facility_type} | "
                f"{status} | "
                f"Key Version: "
                f"{facility.key_version}"
            )


# ============================================================
# HEALTHCARE INC. DEMONSTRATION
# ============================================================

def main():

    print("=" * 70)

    print(
        "HEALTHCARE INC. "
        "CENTRALIZED RABIN KEY MANAGEMENT SERVICE"
    )

    print("=" * 70)

    # --------------------------------------------------------
    # Create centralized KMS
    # --------------------------------------------------------

    kms = HealthcareKMS(
        key_size=1024
    )

    # --------------------------------------------------------
    # Register hospitals and clinics
    # --------------------------------------------------------

    if not kms.facilities:

        kms.register_facility(
            "H001",
            "City General Hospital",
            "Hospital"
        )

        kms.register_facility(
            "H002",
            "Central Medical Hospital",
            "Hospital"
        )

        kms.register_facility(
            "C001",
            "Downtown Health Clinic",
            "Clinic"
        )

    # --------------------------------------------------------
    # Display facilities
    # --------------------------------------------------------

    kms.show_facilities()

    # ========================================================
    # KEY DISTRIBUTION
    # ========================================================

    print("\n" + "-" * 70)

    print(
        "KEY DISTRIBUTION"
    )

    print("-" * 70)

    public_key, private_key = (
        kms.distribute_keys(
            "H001"
        )
    )

    print(
        "\nHospital H001 Public Key:"
    )

    print(
        public_key
    )

    print(
        "\nHospital H001 Private Key:"
    )

    print(
        private_key
    )

    # ========================================================
    # RABIN ENCRYPTION
    # ========================================================

    print("\n" + "-" * 70)

    print(
        "RABIN ENCRYPTION"
    )

    print("-" * 70)

    patient_data = (
        "Patient ID: P1001 | "
        "Diagnosis: Confidential"
    )

    ciphertext = (
        kms.rabin.encrypt(
            patient_data,
            public_key
        )
    )

    print(
        "\nOriginal Patient Data:"
    )

    print(
        patient_data
    )

    print(
        "\nEncrypted Patient Data:"
    )

    print(
        ciphertext
    )

    # ========================================================
    # RABIN DECRYPTION
    # ========================================================

    print("\n" + "-" * 70)

    print(
        "RABIN DECRYPTION"
    )

    print("-" * 70)

    decrypted_data = (
        kms.rabin.decrypt(
            ciphertext,
            private_key
        )
    )

    print(
        "\nDecrypted Patient Data:"
    )

    print(
        decrypted_data
    )

    # ========================================================
    # KEY REVOCATION
    # ========================================================

    print("\n" + "-" * 70)

    print(
        "KEY REVOCATION"
    )

    print("-" * 70)

    kms.revoke_key(
        "H002",
        reason=(
            "Facility compromised"
        )
    )

    try:

        kms.distribute_keys(
            "H002"
        )

    except PermissionError as e:

        print(
            "\nAccess denied:"
        )

        print(
            e
        )

    # ========================================================
    # KEY RENEWAL
    # ========================================================

    print("\n" + "-" * 70)

    print(
        "KEY RENEWAL"
    )

    print("-" * 70)

    kms.renew_key(
        "C001"
    )

    print(
        "\nClinic C001 key renewed."
    )

    # ========================================================
    # AUTOMATIC RENEWAL
    # ========================================================

    print("\n" + "-" * 70)

    print(
        "AUTOMATIC KEY RENEWAL CHECK"
    )

    print("-" * 70)

    kms.automatic_renewal()

    print(
        "Automatic renewal check completed."
    )

    # ========================================================
    # AUDIT INFORMATION
    # ========================================================

    print("\n" + "-" * 70)

    print(
        "AUDIT LOG"
    )

    print("-" * 70)

    if os.path.exists(
        "audit.log"
    ):

        with open(
            "audit.log",
            "r"
        ) as file:

            print(
                file.read()
            )

    print(
        "\nHealthcare Inc. "
        "KMS demonstration completed."
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

'''
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.number import getPrime
from Cryptodome.Hash import SHA256
import json
import os
from datetime import datetime, timedelta


# ---------- KEY MANAGEMENT SERVICE ----------

class KeyManagementService:

    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.keys = {}
        self.revoked = set()
        self.audit_log = []

    # ---------- AUDITING ----------

    def log(self, operation, facility):
        entry = {
            "time": str(datetime.now()),
            "operation": operation,
            "facility": facility
        }

        self.audit_log.append(entry)

    # ---------- RABIN KEY GENERATION ----------

    def generate_keys(self, facility):

        # Generate two primes p and q
        p = getPrime(self.key_size // 2)
        q = getPrime(self.key_size // 2)

        # Rabin requires p and q to be 3 mod 4
        while p % 4 != 3:
            p = getPrime(self.key_size // 2)

        while q % 4 != 3:
            q = getPrime(self.key_size // 2)

        n = p * q

        self.keys[facility] = {
            "public_key": n,
            "private_key": (p, q),
            "created": datetime.now(),
            "expires": datetime.now() + timedelta(days=365)
        }

        self.log("KEY_GENERATED", facility)

    # ---------- KEY DISTRIBUTION ----------

    def get_keys(self, facility):

        if facility not in self.keys:
            raise Exception("Facility not registered.")

        if facility in self.revoked:
            raise Exception("Facility key has been revoked.")

        self.log("KEY_DISTRIBUTED", facility)

        return self.keys[facility]

    # ---------- KEY REVOCATION ----------

    def revoke_key(self, facility):

        if facility in self.keys:
            self.revoked.add(facility)
            self.log("KEY_REVOKED", facility)

    # ---------- KEY RENEWAL ----------

    def renew_key(self, facility):

        if facility not in self.keys:
            raise Exception("Facility not registered.")

        self.generate_keys(facility)
        self.log("KEY_RENEWED", facility)

    # ---------- AUTOMATIC RENEWAL ----------

    def renew_expired_keys(self):

        now = datetime.now()

        for facility, data in list(self.keys.items()):

            if now >= data["expires"]:
                self.renew_key(facility)

    # ---------- DISPLAY LOG ----------

    def show_audit_log(self):

        print("\nAUDIT LOG")

        for entry in self.audit_log:
            print(entry)


# ---------- RABIN ENCRYPTION ----------

def rabin_encrypt(message, public_key):

    n = public_key

    # Convert message into integer
    m = int.from_bytes(
        message.encode(),
        "big"
    )

    if m >= n:
        raise ValueError("Message is too large for the key.")

    # Rabin encryption
    c = pow(m, 2, n)

    return c


# ---------- RABIN DECRYPTION ----------

def rabin_decrypt(ciphertext, private_key):

    p, q = private_key

    # Calculate square roots modulo p and q
    mp = pow(
        ciphertext,
        (p + 1) // 4,
        p
    )

    mq = pow(
        ciphertext,
        (q + 1) // 4,
        q
    )

    # Extended Euclidean algorithm
    def inverse(a, m):
        return pow(a, -1, m)

    yp = inverse(p, q)
    yq = inverse(q, p)

    # CRT combinations
    r1 = (yp * p * mq + yq * q * mp) % (p * q)
    r2 = (p * q - r1) % (p * q)
    r3 = (yp * p * mq - yq * q * mp) % (p * q)
    r4 = (p * q - r3) % (p * q)

    roots = [r1, r2, r3, r4]

    # Try roots until a valid message is found
    for root in roots:

        try:
            message = root.to_bytes(
                (root.bit_length() + 7) // 8,
                "big"
            ).decode()

            return message

        except UnicodeDecodeError:
            continue

    raise ValueError("Unable to decrypt message.")


# ---------- MAIN PROGRAM ----------

print("HEALTHCARE INC. KEY MANAGEMENT SERVICE")

# Create KMS with configurable 1024-bit keys
kms = KeyManagementService(1024)

# Register hospitals and clinics
kms.generate_keys("Hospital-A")
kms.generate_keys("Hospital-B")
kms.generate_keys("Clinic-C")

print("\nFacilities registered:")
print("1. Hospital-A")
print("2. Hospital-B")
print("3. Clinic-C")


# ---------- KEY DISTRIBUTION ----------

print("\nKEY DISTRIBUTION")

hospital_keys = kms.get_keys("Hospital-A")

print("Hospital-A Public Key:")
print(hospital_keys["public_key"])

print("\nHospital-A Private Key:")
print(hospital_keys["private_key"])


# ---------- RABIN ENCRYPTION ----------

message = "Patient Record 12345"

ciphertext = rabin_encrypt(
    message,
    hospital_keys["public_key"]
)

print("\nEncrypted Patient Data:")
print(ciphertext)


# ---------- RABIN DECRYPTION ----------

plaintext = rabin_decrypt(
    ciphertext,
    hospital_keys["private_key"]
)

print("\nDecrypted Patient Data:")
print(plaintext)


# ---------- KEY REVOCATION ----------

print("\nKEY REVOCATION")

kms.revoke_key("Hospital-B")

try:
    kms.get_keys("Hospital-B")

except Exception as e:
    print("Access denied:", e)


# ---------- KEY RENEWAL ----------

print("\nKEY RENEWAL")

kms.renew_key("Clinic-C")

print("Clinic-C key successfully renewed.")


# ---------- AUDITING ----------

kms.show_audit_log()


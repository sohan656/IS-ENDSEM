'''
SECURE INTER-BANK TRANSACTION MANAGEMENT SYSTEM
Scenario
A national banking organization operates multiple branches that communicate with a centralized banking server. Customers initiate financial transactions through their respective branches, while the central server securely processes, verifies and stores transaction records.

The system must ensure confidentiality, integrity, authentication, secure key management and encrypted computation. All communication between the client and server must take place using Python socket programming.
1. Client Side — Bank Branch (8 Marks)
A bank employee enters the following transaction details:
Field	Description
Transaction ID	Unique identifier
Sender Account	Account initiating transfer
Receiver Account	Destination account
Amount	Transaction amount
Department	Department processing transaction

Before sending the transaction to the server, the client must perform the following operations.

A. Secure Key Exchange (2 marks)

Implement the Diffie-Hellman key exchange algorithm between the client and server.
- Both parties generate their private and public values.
- Exchange public values using sockets.
- Generate a common shared secret.
- Derive a 32-byte AES key using HKDF with SHA-256.
B. Transaction Encryption (2 marks)

Encrypt the complete transaction record using AES-256 GCM.
- Generate a random nonce.
- Encrypt the transaction details.
- Generate and transmit the authentication tag.
C. Hashing and Digital Signature (2 marks)
- Generate a SHA-256 hash of the transaction record.
- Generate an RSA-2048 key pair.
- Sign the transaction hash using RSA with PKCS#1 v1.5.
- Send the signature and the client's public key to the server.
D. Homomorphic Encryption (2 marks)

Encrypt the transaction amount using the Paillier cryptosystem using the server's public key.

The encrypted amount must be transmitted separately from the AES-encrypted transaction record.
2. Server Side — Central Banking Server (8 Marks)
The central server must receive transaction packages and perform the following operations.

A. Authentication and Integrity Verification (2 marks)
- Establish the same shared secret using Diffie-Hellman.
- Derive the AES-256 key.
- Decrypt the transaction using AES-GCM.
- Verify the authentication tag.
- Verify the RSA digital signature.
- Recompute the SHA-256 hash and compare it with the received hash.
Reject any transaction that fails verification.

B. Replay Attack Prevention (2 marks)

Every transaction must contain a unique transaction ID and timestamp.
- Reject transactions with duplicate IDs.
- Reject transactions older than 120 seconds.
- Record rejected transactions in an audit log.
C. Searchable Encryption (2 marks)

Create an HMAC-SHA256 searchable index using the transaction's department.

The administrator must be able to search for transactions belonging to a particular department without decrypting all transaction records.

The search operation should display only matching transaction IDs.

D. Homomorphic Aggregation (2 marks)

The server receives Paillier-encrypted transaction amounts.
- Store the encrypted amounts.
- Multiply selected ciphertexts modulo \(n^2\).
- Decrypt only the final aggregate.
- Display the total transaction amount.
Individual transaction amounts must not be decrypted during aggregation.
3. Role-Based Access Control and Integration (4 Marks)
Implement a menu-driven system with the following roles.

Client Menu — Bank Employee
Server Menu — Administrator

'''


import socket
import json
import time
import math
import hmac
import hashlib
import secrets
import threading

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Util.number import getPrime, isPrime, inverse


HOST = "127.0.0.1"
PORT = 5050

# Demo accounts
users = {
    "employee": ("1234", "Employee"),
    "admin": ("admin123", "Admin")
}

transactions = {}
search_index = {}
audit_log = []
registered_keys = {}
sessions = {}

search_key = secrets.token_bytes(32)
lock = threading.RLock()


# ==================================================
# 1. AUDIT LOGGING
# ==================================================

def audit(action, details=""):
    entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "details": details
    }

    audit_log.append(entry)
    print("[AUDIT]", entry)


# ==================================================
# 2. DIFFIE-HELLMAN PARAMETERS
# ==================================================

# Generate a safe prime p = 2q + 1
q = getPrime(256)
p = 2 * q + 1

while not isPrime(p):
    q = getPrime(256)
    p = 2 * q + 1

g = 4

# Store pending and established DH sessions
dh_sessions = {}


def derive_aes_key(shared_secret):
    # Convert shared integer to bytes
    shared_bytes = shared_secret.to_bytes(
        (p.bit_length() + 7) // 8,
        "big"
    )

    # Derive a 32-byte AES-256 key using HKDF-SHA256
    return HKDF(
        shared_bytes,
        32,
        b"Bank-DH-v1",
        SHA256
    )


def start_dh(username):
    private = secrets.randbelow(q - 1) + 1
    public = pow(g, private, p)

    dh_sessions[username] = {
        "private": private,
        "public": public,
        "key": None
    }

    return {
        "p": str(p),
        "g": str(g),
        "server_public": str(public)
    }


def finish_dh(username, client_public):
    session = dh_sessions.get(username)

    if session is None:
        return {"error": "Start DH first"}

    client_public = int(client_public)

    if not 1 < client_public < p - 1:
        return {"error": "Invalid DH public value"}

    shared = pow(
        client_public,
        session["private"],
        p
    )

    session["key"] = derive_aes_key(shared)

    audit("DH_ESTABLISHED", username)

    return {"success": True}


# ==================================================
# 3. AES-GCM DECRYPTION
# ==================================================

def aes_decrypt(package, key):
    nonce = bytes.fromhex(package["nonce"])
    ciphertext = bytes.fromhex(package["ciphertext"])
    tag = bytes.fromhex(package["tag"])

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    return cipher.decrypt_and_verify(
        ciphertext,
        tag
    )


# ==================================================
# 4. RSA SIGNATURE VERIFICATION
# ==================================================

def verify_signature(data, signature, public_key):
    try:
        digest = SHA256.new(data)

        pkcs1_15.new(public_key).verify(
            digest,
            bytes.fromhex(signature)
        )

        return True

    except (ValueError, TypeError):
        return False


# ==================================================
# 5. PAILLIER KEY GENERATION
# ==================================================

def paillier_keygen():
    p1 = getPrime(256)
    q1 = getPrime(256)

    while p1 == q1:
        q1 = getPrime(256)

    n = p1 * q1
    ns = n * n
    lam = math.lcm(p1 - 1, q1 - 1)
    mu = inverse(lam, n)

    return (n, ns, n + 1), (lam, mu)


def paillier_decrypt(ciphertext):
    n, ns, g = paillier_public
    lam, mu = paillier_private

    x = pow(ciphertext, lam, ns)

    return (((x - 1) // n) * mu) % n


paillier_public, paillier_private = paillier_keygen()


# ==================================================
# 6. HMAC SEARCHABLE INDEX
# ==================================================

def make_token(word):
    return hmac.new(
        search_key,
        word.lower().encode(),
        hashlib.sha256
    ).hexdigest()


def index_transaction(tx_id, department):
    token = make_token(department)

    search_index.setdefault(
        token, set()
    ).add(tx_id)


# ==================================================
# 7. VERIFY AND RECEIVE TRANSACTION
# ==================================================

def receive_transaction(username, package):
    session = dh_sessions.get(username)

    if session is None or session["key"] is None:
        return {"error": "Establish DH first"}

    tx_id = package.get("transaction_id", "")

    # Reject duplicate transaction IDs
    if tx_id in transactions:
        audit("REPLAY_REJECTED", tx_id)
        return {"error": "Duplicate transaction"}

    # Verify timestamp freshness
    timestamp = float(package["timestamp"])

    if abs(time.time() - timestamp) > 120:
        audit("EXPIRED_TRANSACTION", tx_id)
        return {"error": "Transaction older than 120 seconds"}

    # Recreate signed bytes without the signature
    signed_fields = {
        k: v for k, v in package.items()
        if k != "signature"
    }

    signed_bytes = json.dumps(
        signed_fields,
        sort_keys=True
    ).encode()

    # Verify using previously registered RSA public key
    public_key = registered_keys.get(username)

    if public_key is None:
        return {"error": "RSA public key not registered"}

    if not verify_signature(
        signed_bytes,
        package["signature"],
        public_key
    ):
        audit("SIGNATURE_FAILED", tx_id)
        return {"error": "Invalid RSA signature"}

    try:
        # Decrypt AES-GCM transaction
        plaintext = aes_decrypt(
            package,
            session["key"]
        )

        # Compare SHA-256 hash
        calculated_hash = SHA256.new(
            plaintext
        ).hexdigest()

        if not hmac.compare_digest(
            calculated_hash,
            package["hash"]
        ):
            audit("HASH_FAILED", tx_id)
            return {"error": "SHA-256 mismatch"}

        transaction = json.loads(plaintext.decode())

        if transaction["transaction_id"] != tx_id:
            return {"error": "Transaction ID mismatch"}

        amount = int(transaction["amount"])
        department = transaction["department"]

        if amount < 0 or amount >= paillier_public[0]:
            return {"error": "Invalid amount"}

        encrypted_amount = int(
            package["encrypted_amount"]
        )

        n, ns, g = paillier_public

        if not (
            1 <= encrypted_amount < ns
            and math.gcd(encrypted_amount, n) == 1
        ):
            return {"error": "Invalid Paillier ciphertext"}

    except (ValueError, KeyError, TypeError, UnicodeError):
        audit("TRANSACTION_REJECTED", tx_id)
        return {"error": "Invalid encrypted transaction"}

    # Store the encrypted package and searchable metadata
    transactions[tx_id] = package

    index_transaction(tx_id, department)

    audit("TRANSACTION_ACCEPTED", tx_id)

    return {
        "success": True,
        "transaction_id": tx_id,
        "signature_valid": True,
        "hash_valid": True
    }


# ==================================================
# 8. HOMOMORPHIC AGGREGATION
# ==================================================

def homomorphic_total(selected_ids):
    if not selected_ids:
        return {"error": "Select at least one transaction"}

    if len(selected_ids) != len(set(selected_ids)):
        return {"error": "Duplicate IDs in selection"}

    n, ns, g = paillier_public
    encrypted_total = 1

    for tx_id in selected_ids:
        if tx_id not in transactions:
            return {"error": f"Unknown transaction: {tx_id}"}

        package = transactions[tx_id]

        # Reverify signature before aggregation
        owner = package["owner"]
        public_key = registered_keys[owner]

        signed_fields = {
            k: v for k, v in package.items()
            if k != "signature"
        }

        signed_bytes = json.dumps(
            signed_fields,
            sort_keys=True
        ).encode()

        if not verify_signature(
            signed_bytes,
            package["signature"],
            public_key
        ):
            audit("TAMPERING_DETECTED", tx_id)
            return {"error": f"Signature invalid: {tx_id}"}

        ciphertext = int(package["encrypted_amount"])

        # Multiply Paillier ciphertexts modulo n²
        encrypted_total = (
            encrypted_total * ciphertext
        ) % ns

    # Decrypt only the final aggregate
    total = paillier_decrypt(encrypted_total)

    return {
        "encrypted_total": str(encrypted_total),
        "decrypted_total": total
    }


# ==================================================
# 9. LOGIN AND SESSION HANDLING
# ==================================================

def login(username, password):
    username = username.strip().lower()

    if username not in users or users[username][0] != password:
        audit("LOGIN_FAILED", username)
        return {"error": "Invalid credentials"}

    token = secrets.token_hex(24)
    sessions[token] = username

    return {
        "success": True,
        "token": token,
        "role": users[username][1]
    }


def get_user(request):
    return sessions.get(request.get("token", ""))


# ==================================================
# 10. SERVER REQUEST HANDLER
# ==================================================

def handle(request):
    action = request.get("action")

    if action == "login":
        return login(
            request.get("username", ""),
            request.get("password", "")
        )

    username = get_user(request)

    if username is None:
        return {"error": "Login required"}

    role = users[username][1]

    if action == "logout":
        sessions.pop(request.get("token"), None)
        return {"success": True}

    if action == "register_key" and role == "Employee":
        if username in registered_keys:
            return {"error": "RSA key already registered"}

        try:
            key = RSA.import_key(request["public_key"])

            if key.has_private():
                return {"error": "Public key required"}

            registered_keys[username] = key

            audit("RSA_KEY_REGISTERED", username)
            return {"success": True}

        except (ValueError, IndexError, TypeError):
            return {"error": "Invalid RSA key"}

    if action == "dh_start" and role == "Employee":
        return start_dh(username)

    if action == "dh_finish" and role == "Employee":
        return finish_dh(
            username,
            request["client_public"]
        )

    if action == "public_keys":
        return {
            "paillier": [str(x) for x in paillier_public]
        }

    if action == "submit" and role == "Employee":
        return receive_transaction(
            username,
            request["package"]
        )

    if action == "status" and role == "Employee":
        tx_id = request.get("transaction_id", "")

        package = transactions.get(tx_id)

        if package and package.get("owner") == username:
            return {"status": "Accepted"}

        return {"status": "Not found"}

    if action == "list" and role == "Admin":
        return {"transactions": list(transactions.keys())}

    if action == "verify" and role == "Admin":
        tx_id = request.get("transaction_id", "")

        if tx_id not in transactions:
            return {"error": "Transaction not found"}

        package = transactions[tx_id]
        owner = package["owner"]

        fields = {
            k: v for k, v in package.items()
            if k != "signature"
        }

        valid = verify_signature(
            json.dumps(fields, sort_keys=True).encode(),
            package["signature"],
            registered_keys[owner]
        )

        return {"signature_valid": valid}

    if action == "search" and role == "Admin":
        department = request.get("department", "")

        matches = search_index.get(
            make_token(department),
            set()
        )

        return {"matches": sorted(matches)}

    if action == "total" and role == "Admin":
        return homomorphic_total(
            request.get("transaction_ids", [])
        )

    if action == "audit" and role == "Admin":
        return {"audit_log": audit_log}

    return {"error": "Access denied"}


# ==================================================
# 11. TCP SOCKET SERVER
# ==================================================

def client_handler(conn):
    try:
        with conn.makefile("rwb") as stream:
            for line in stream:
                try:
                    request = json.loads(line.decode())

                    # Lock shared dictionaries during processing
                    with lock:
                        response = handle(request)

                except Exception as e:
                    response = {
                        "error": f"Request failed: {type(e).__name__}"
                    }

                stream.write(
                    (json.dumps(response) + "\n").encode()
                )
                stream.flush()

    finally:
        conn.close()


def main():
    print("Bank server running on port", PORT)

    with socket.socket() as server:
        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind((HOST, PORT))
        server.listen(5)

        while True:
            conn, address = server.accept()

            threading.Thread(
                target=client_handler,
                args=(conn,),
                daemon=True
            ).start()


if __name__ == "__main__":
    main()

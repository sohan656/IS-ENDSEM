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
import secrets

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Random import get_random_bytes


HOST = "127.0.0.1"
PORT = 5050

token = None
role = None
username = None

aes_key = None
paillier_public = None

# Generate RSA-2048 signing key for the client
rsa_key = RSA.generate(2048)


# ==================================================
# 1. SOCKET COMMUNICATION
# ==================================================

def send(request):

    # Connect to the bank server
    with socket.create_connection((HOST, PORT)) as sock:

        # Send JSON request followed by newline
        sock.sendall(
            (json.dumps(request) + "\n").encode()
        )

        # Read server response
        with sock.makefile("r") as stream:
            response = json.loads(stream.readline())

    return response


def request(action, **kwargs):

    # Add session token to every authenticated request
    data = {
        "action": action,
        "token": token
    }

    data.update(kwargs)

    return send(data)


# ==================================================
# 2. LOGIN AND LOGOUT
# ==================================================

def login():
    global token, role, username

    user = input("Username: ").strip().lower()
    password = input("Password: ")

    response = send({
        "action": "login",
        "username": user,
        "password": password
    })

    if not response.get("success"):
        print(response.get("error"))
        return

    token = response["token"]
    role = response["role"]
    username = user

    print("Login successful")
    print("Role:", role)


def logout():
    global token, role, username, aes_key

    if token:
        print(request("logout"))

    token = None
    role = None
    username = None
    aes_key = None


# ==================================================
# 3. REGISTER RSA PUBLIC KEY
# ==================================================

def register_rsa_key():

    # Send only the RSA public key to the server
    public_key = rsa_key.publickey().export_key().decode()

    response = request(
        "register_key",
        public_key=public_key
    )

    print(response)


# ==================================================
# 4. DIFFIE-HELLMAN KEY EXCHANGE
# ==================================================

def establish_connection():
    global aes_key, paillier_public

    response = request("dh_start")

    if "error" in response:
        print(response)
        return

    p = int(response["p"])
    g = int(response["g"])
    server_public = int(response["server_public"])

    # Generate client private and public values
    private = secrets.randbelow((p - 1) // 2 - 1) + 1
    client_public = pow(g, private, p)

    # Calculate shared secret using server public value
    shared_secret = pow(server_public, private, p)

    shared_bytes = shared_secret.to_bytes(
        (p.bit_length() + 7) // 8,
        "big"
    )

    # Derive 32-byte AES-256 key using HKDF-SHA256
    aes_key = HKDF(
        shared_bytes,
        32,
        b"Bank-DH-v1",
        SHA256
    )

    response = request(
        "dh_finish",
        client_public=str(client_public)
    )

    if not response.get("success"):
        aes_key = None
        print(response)
        return

    # Obtain server's Paillier public key
    response = request("public_keys")

    paillier_public = tuple(
        int(x) for x in response["paillier"]
    )

    print("Diffie-Hellman exchange successful")
    print("AES key size:", len(aes_key), "bytes")
    print("Shared AES key established")


# ==================================================
# 5. AES-256 GCM ENCRYPTION
# ==================================================

def aes_encrypt(message):

    cipher = AES.new(aes_key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(
        message.encode()
    )

    return (
        cipher.nonce.hex(),
        ciphertext.hex(),
        tag.hex()
    )


# ==================================================
# 6. SHA-256 HASHING
# ==================================================

def sha256_hash(message):

    return SHA256.new(
        message.encode()
    ).hexdigest()


# ==================================================
# 7. RSA DIGITAL SIGNATURE
# ==================================================

def sign_data(data):

    digest = SHA256.new(data)

    # Sign using RSA private key and PKCS#1 v1.5
    signature = pkcs1_15.new(
        rsa_key
    ).sign(digest)

    return signature.hex()


# ==================================================
# 8. PAILLIER ENCRYPTION
# ==================================================

def paillier_encrypt(amount):

    n, ns, g = paillier_public

    # Generate r coprime to n
    while True:
        r = secrets.randbelow(n - 1) + 1

        if math.gcd(r, n) == 1:
            break

    return (
        pow(g, amount, ns) *
        pow(r, n, ns)
    ) % ns


# ==================================================
# 9. SUBMIT TRANSACTION
# ==================================================

def submit_transaction():

    if aes_key is None or paillier_public is None:
        print("Establish secure connection first")
        return

    tx_id = input("Transaction ID: ").strip()
    sender = input("Sender Account: ").strip()
    receiver = input("Receiver Account: ").strip()
    department = input("Department: ").strip()

    try:
        amount = int(input("Amount: "))

    except ValueError:
        print("Invalid amount")
        return

    if not all([tx_id, sender, receiver, department]):
        print("All fields are required")
        return

    if not 0 <= amount < paillier_public[0]:
        print("Amount outside Paillier range")
        return

    # Create transaction record
    transaction = {
        "transaction_id": tx_id,
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "department": department
    }

    # Convert transaction into consistent JSON text
    message = json.dumps(
        transaction,
        sort_keys=True
    )

    # Calculate SHA-256 hash
    message_hash = sha256_hash(message)

    # Encrypt complete transaction using AES-GCM
    nonce, ciphertext, tag = aes_encrypt(message)

    # Encrypt amount separately using Paillier
    encrypted_amount = paillier_encrypt(amount)

    # Prepare transaction package
    package = {
        "owner": username,
        "transaction_id": tx_id,
        "timestamp": time.time(),
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag,
        "hash": message_hash,
        "encrypted_amount": str(encrypted_amount)
    }

    # Sign the entire package except the signature itself
    signed_bytes = json.dumps(
        package,
        sort_keys=True
    ).encode()

    package["signature"] = sign_data(signed_bytes)

    # Send encrypted and signed package to server
    response = request(
        "submit",
        package=package
    )

    print("\n--- TRANSACTION OUTPUT ---")
    print("Transaction ID:", tx_id)
    print("SHA-256:", message_hash)
    print("AES Ciphertext:", ciphertext)
    print("AES-GCM Tag:", tag)
    print("Paillier Encrypted Amount:", encrypted_amount)
    print("RSA Signature:", package["signature"])

    print("\nServer Response:", response)


# ==================================================
# 10. VIEW TRANSACTION STATUS
# ==================================================

def transaction_status():

    tx_id = input("Transaction ID: ").strip()

    response = request(
        "status",
        transaction_id=tx_id
    )

    print(response)


# ==================================================
# 11. EMPLOYEE MENU
# ==================================================

def employee_menu():

    while role == "Employee":

        print("\n========== BANK EMPLOYEE ==========")
        print("1. Register RSA Public Key")
        print("2. Establish Secure Connection")
        print("3. Submit Transaction")
        print("4. View Transaction Status")
        print("5. Logout")

        choice = input("Choice: ")

        if choice == "1":
            register_rsa_key()

        elif choice == "2":
            establish_connection()

        elif choice == "3":
            submit_transaction()

        elif choice == "4":
            transaction_status()

        elif choice == "5":
            logout()
            break

        else:
            print("Invalid choice")


# ==================================================
# 12. ADMIN MENU
# ==================================================

def admin_menu():

    while role == "Admin":

        print("\n========== BANK ADMIN ==========")
        print("1. View Transaction IDs")
        print("2. Verify RSA Signature")
        print("3. Search by Department")
        print("4. Homomorphic Total")
        print("5. View Audit Log")
        print("6. Logout")

        choice = input("Choice: ")

        if choice == "1":
            print(request("list"))

        elif choice == "2":
            tx_id = input("Transaction ID: ")

            print(request(
                "verify",
                transaction_id=tx_id
            ))

        elif choice == "3":
            department = input("Department: ")

            print(request(
                "search",
                department=department
            ))

        elif choice == "4":
            ids = input(
                "Transaction IDs (comma separated): "
            )

            selected = [
                x.strip()
                for x in ids.split(",")
                if x.strip()
            ]

            print(request(
                "total",
                transaction_ids=selected
            ))

        elif choice == "5":
            response = request("audit")

            for entry in response.get("audit_log", []):
                print(entry)

        elif choice == "6":
            logout()
            break

        else:
            print("Invalid choice")


# ==================================================
# 13. MAIN MENU
# ==================================================

def main():

    while True:

        print("\n========== BANK CLIENT ==========")
        print("1. Login")
        print("2. Exit")

        choice = input("Choice: ")

        if choice == "1":
            login()

            if role == "Employee":
                employee_menu()

            elif role == "Admin":
                admin_menu()

        elif choice == "2":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

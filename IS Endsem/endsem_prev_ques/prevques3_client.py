
import socket
import json
import math
import secrets
import hashlib

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
from Cryptodome.Util.number import getPrime, isPrime, inverse


HOST = "127.0.0.1"
PORT = 5000

session_token = None
current_role = None
current_username = None

rsa_public = None
paillier_public = None
candidates = {}

# Store voter signing keys during this client session
voter_keys = {}


# ==================================================
# 1. SOCKET COMMUNICATION
# ==================================================

def send_request(request):
    # Open TCP connection to server
    with socket.create_connection((HOST, PORT)) as sock:

        # Send one JSON request followed by newline
        sock.sendall(
            (json.dumps(request) + "\n").encode()
        )

        # Read one JSON response line
        with sock.makefile("r") as stream:
            response = json.loads(stream.readline())

    return response


def authenticated_request(action, **kwargs):
    # Add login token to the request
    request = {
        "action": action,
        "token": session_token
    }

    request.update(kwargs)

    return send_request(request)


# ==================================================
# 2. FETCH ELECTION COMMISSION PUBLIC KEYS
# ==================================================

def fetch_public_keys():
    global rsa_public, paillier_public, candidates

    response = send_request({
        "action": "public_keys"
    })

    # Import RSA public key in PEM format
    rsa_public = RSA.import_key(
        response["rsa_public"]
    )

    # Convert Paillier public values into integers
    paillier_public = tuple(
        int(x) for x in response["paillier_public"]
    )

    candidates = {
        int(k): v
        for k, v in response["candidates"].items()
    }

    print("Election Commission public keys received")
    print("RSA key size:", rsa_public.size_in_bits())


# ==================================================
# 3. SHA-512 HASHING
# ==================================================

def hash_ballot(data):
    return SHA512.new(data).hexdigest()


# ==================================================
# 4. AES-256 CBC ENCRYPTION
# ==================================================

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(data, AES.block_size)
    )

    return cipher.iv, ciphertext


# ==================================================
# 5. RSA ENCRYPTION OF AES SESSION KEY
# ==================================================

def rsa_encrypt_key(key):
    cipher = PKCS1_OAEP.new(
        rsa_public,
        hashAlgo=SHA256
    )

    return cipher.encrypt(key)


# ==================================================
# 6. ELGAMAL KEY GENERATION
# ==================================================

def elgamal_keygen():
    # Generate safe prime p=2q+1
    q = getPrime(256)
    p = 2 * q + 1

    while not isPrime(p):
        q = getPrime(256)
        p = 2 * q + 1

    # Find a generator modulo p
    while True:
        g = secrets.randbelow(p - 3) + 2

        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            break

    # Generate private and public keys
    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)

    return (p, g, y), x


# ==================================================
# 7. ELGAMAL DIGITAL SIGNATURE
# ==================================================

def elgamal_sign(data, public, private):
    p, g, y = public
    x = private

    # Convert SHA-512 digest to an integer
    digest = SHA512.new(data).digest()
    h = int.from_bytes(digest, "big") % (p - 1)

    # Generate k coprime to p-1
    while True:
        k = secrets.randbelow(p - 2) + 1

        if math.gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)

    s = (
        (h - x * r) * inverse(k, p - 1)
    ) % (p - 1)

    return [r, s]


# ==================================================
# 8. PAILLIER ENCRYPTION
# ==================================================

def paillier_encrypt(m):
    n, ns, g = paillier_public

    while True:
        r = secrets.randbelow(n - 1) + 1

        if math.gcd(r, n) == 1:
            break

    return (
        pow(g, m, ns) *
        pow(r, n, ns)
    ) % ns


# ==================================================
# 9. PREPARE SIGNED BALLOT DATA
# ==================================================

def signed_data(packet):
    # Exclude signature field when preparing signed bytes
    data = {
        k: v
        for k, v in packet.items()
        if k != "signature"
    }

    return json.dumps(
        data,
        sort_keys=True
    ).encode()


# ==================================================
# 10. REGISTER VOTER SIGNING KEY
# ==================================================

def register_voter_key():
    if current_username not in voter_keys:
        public, private = elgamal_keygen()

        voter_keys[current_username] = {
            "public": public,
            "private": private
        }

    public = voter_keys[current_username]["public"]

    response = authenticated_request(
        "register_key",
        public_key=[str(x) for x in public]
    )

    print(response)


# ==================================================
# 11. CREATE AND SUBMIT BALLOT
# ==================================================

def cast_vote():
    if current_username not in voter_keys:
        print("Register your signing key first")
        return

    constituency = input("Constituency ID: ").strip()

    print("\nCandidates:")

    for cid, name in candidates.items():
        print(cid, name)

    try:
        candidate = int(input("Candidate ID: "))

    except ValueError:
        print("Invalid candidate")
        return

    if candidate not in candidates or not constituency:
        print("Invalid ballot")
        return

    ballot_id = secrets.token_hex(8)

    # Create ballot dictionary
    ballot = {
        "ballot_id": ballot_id,
        "constituency": constituency,
        "candidate": candidate
    }

    # Convert ballot to JSON bytes
    ballot_bytes = json.dumps(
        ballot,
        sort_keys=True
    ).encode()

    # Generate SHA-512 hash
    ballot_hash = hash_ballot(ballot_bytes)

    # Generate random AES-256 session key
    aes_key = get_random_bytes(32)

    # Encrypt ballot using AES-256 CBC
    iv, ciphertext = aes_encrypt(
        ballot_bytes,
        aes_key
    )

    # Encrypt AES key using RSA-4096 public key
    encrypted_key = rsa_encrypt_key(aes_key)

    # Encrypt one-hot vote representation
    encrypted_votes = {}

    for cid in candidates:
        value = 1 if cid == candidate else 0

        encrypted_votes[str(cid)] = str(
            paillier_encrypt(value)
        )

    # Prepare packet for server
    packet = {
        "voter_id": current_username,
        "ballot_id": ballot_id,
        "ballot_hash": ballot_hash,
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "encrypted_key": encrypted_key.hex(),
        "encrypted_votes": encrypted_votes
    }

    # Sign packet using voter ElGamal private key
    public = voter_keys[current_username]["public"]
    private = voter_keys[current_username]["private"]

    signature = elgamal_sign(
        signed_data(packet),
        public,
        private
    )

    # JSON stores large signature integers as strings
    packet["signature"] = [
        str(x) for x in signature
    ]

    print("\n--- CLIENT ENCRYPTION OUTPUT ---")
    print("Ballot ID:", ballot_id)
    print("SHA-512:", ballot_hash)
    print("AES key size:", len(aes_key), "bytes")
    print("AES ciphertext:", ciphertext.hex())
    print("RSA encrypted AES key:", encrypted_key.hex())
    print("ElGamal signature:", signature)
    print("Paillier encrypted votes:", encrypted_votes)

    # Submit packet to Election Commission
    response = authenticated_request(
        "vote",
        packet=packet
    )

    print("\n--- SERVER RESPONSE ---")
    print(json.dumps(response, indent=2))


# ==================================================
# 12. LOGIN AND LOGOUT
# ==================================================

def login():
    global session_token, current_role, current_username

    username = input("Username: ").strip().lower()
    password = input("Password: ")

    response = send_request({
        "action": "login",
        "username": username,
        "password": password
    })

    if not response.get("success"):
        print(response.get("error"))
        return

    session_token = response["token"]
    current_role = response["role"]
    current_username = response["username"]

    print("Login successful")
    print("Role:", current_role)


def logout():
    global session_token, current_role, current_username

    if session_token:
        print(authenticated_request("logout"))

    session_token = None
    current_role = None
    current_username = None


# ==================================================
# 13. VOTER MENU
# ==================================================

def voter_menu():
    while current_role == "Voter":
        print("\n--- VOTER MENU ---")
        print("1. Register ElGamal Public Key")
        print("2. Cast Vote")
        print("3. Logout")

        choice = input("Choice: ")

        if choice == "1":
            register_voter_key()

        elif choice == "2":
            cast_vote()

        elif choice == "3":
            logout()
            break

        else:
            print("Invalid choice")


# ==================================================
# 14. ADMIN AND AUDITOR MENU
# ==================================================

def official_menu():
    while current_role in ("Admin", "Auditor"):
        print("\n--- ELECTION COMMISSION ---")
        print("1. Verify Stored Ballot")
        print("2. Search Constituency")
        print("3. Search Time Range")
        print("4. View Audit Log")

        if current_role == "Admin":
            print("5. Final Threshold Tally")
            print("6. Tamper Ballot (Demo)")

        print("7. Logout")

        choice = input("Choice: ")

        if choice == "1":
            ballot_id = input("Ballot ID: ")

            response = authenticated_request(
                "verify",
                ballot_id=ballot_id
            )

            print(response)

        elif choice == "2":
            constituency = input("Constituency ID: ")

            response = authenticated_request(
                "search",
                constituency=constituency
            )

            print(response)

        elif choice == "3":
            start = input("Start Unix timestamp: ")
            end = input("End Unix timestamp: ")

            response = authenticated_request(
                "search_time",
                start=start,
                end=end
            )

            print(response)

        elif choice == "4":
            response = authenticated_request("audit")

            for entry in response.get("audit_log", []):
                print(entry)

        elif choice == "5" and current_role == "Admin":
            print("Authorities: A1, A2, A3")

            first = input("First authority: ").upper()
            second = input("Second authority: ").upper()

            response = authenticated_request(
                "tally",
                first=first,
                second=second
            )

            print(response)

        elif choice == "6" and current_role == "Admin":
            ballot_id = input("Ballot ID: ")

            response = authenticated_request(
                "tamper",
                ballot_id=ballot_id
            )

            print(response)

        elif choice == "7":
            logout()
            break

        else:
            print("Invalid choice")


# ==================================================
# 15. MAIN MENU
# ==================================================

def main():
    fetch_public_keys()

    while True:
        print("\n========== E-VOTING CLIENT ==========")
        print("1. Login")
        print("2. Exit")

        choice = input("Choice: ")

        if choice == "1":
            login()

            if current_role == "Voter":
                voter_menu()

            elif current_role in ("Admin", "Auditor"):
                official_menu()

        elif choice == "2":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

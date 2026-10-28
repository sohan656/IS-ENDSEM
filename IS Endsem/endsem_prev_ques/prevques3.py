
import time
import json
import math
import hmac
import hashlib
import secrets
from datetime import datetime, timezone

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA512, SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.number import getPrime, isPrime, inverse


# ============================================================
# 1. CONFIGURATION
# ============================================================

CANDIDATES = {
    1: "Candidate A",
    2: "Candidate B",
    3: "Candidate C"
}

# Voting remains open for 10 minutes after program starts.
VOTING_START = time.time()
VOTING_END = VOTING_START + 600

# Stores encrypted ballots and search tokens.
ballots = {}
search_index = {}

# Stores voter IDs that have already voted.
voted = set()

# Stores security-related operations.
audit_log = []

# Simple role-based login dictionary.
users = {
    "V101": {"password": "1111", "role": "Voter"},
    "V102": {"password": "2222", "role": "Voter"},
    "V103": {"password": "3333", "role": "Voter"},
    "admin": {"password": "admin123", "role": "Officer"},
    "auditor": {"password": "audit123", "role": "Auditor"}
}

current_user = None

# RSA-4096 key pair belonging to Election Commission.
print("Generating RSA-4096 keys...")
ec_rsa_key = RSA.generate(4096)

# Separate RSA key used by simulated timestamp authority.
timestamp_key = RSA.generate(2048)

# HMAC secret used for searchable index.
search_key = get_random_bytes(32)


# ============================================================
# 2. AUDIT LOGGING
# ============================================================

def audit(action, details=""):

    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "details": details
    }

    audit_log.append(entry)

    print("[AUDIT]", action, details)


def show_audit():

    if not audit_log:
        print("No audit records")
        return

    for entry in audit_log:
        print(entry)


# ============================================================
# 3. SHA-512 HASHING
# ============================================================

def sha512_hash(data):

    # data must be bytes.
    # digest() returns 64 bytes.
    return SHA512.new(data).digest()


# ============================================================
# 4. AES-256 CBC
# ============================================================

def aes_encrypt(data, key):

    # key must contain 32 bytes for AES-256.
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(data, AES.block_size)
    )

    return cipher.iv, ciphertext


def aes_decrypt(iv, ciphertext, key):

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv
    )

    return unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )


# ============================================================
# 5. RSA-4096 ENCRYPTION OF AES KEY
# ============================================================

def rsa_encrypt_key(aes_key):

    # Encrypt AES key using Election Commission public key.
    cipher = PKCS1_OAEP.new(
        ec_rsa_key.publickey(),
        hashAlgo=SHA256
    )

    return cipher.encrypt(aes_key)


def rsa_decrypt_key(encrypted_key):

    # Decrypt AES key using Election Commission private key.
    cipher = PKCS1_OAEP.new(
        ec_rsa_key,
        hashAlgo=SHA256
    )

    return cipher.decrypt(encrypted_key)


# ============================================================
# 6. ELGAMAL DIGITAL SIGNATURE
# ============================================================

def elgamal_keygen():

    # Generate a safe prime p = 2q + 1.
    q = getPrime(256)
    p = 2 * q + 1

    while not isPrime(p):
        q = getPrime(256)
        p = 2 * q + 1

    # Find a generator of the group modulo p.
    while True:
        g = secrets.randbelow(p - 3) + 2

        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            break

    # Private key x and public component y.
    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)

    return (p, g, y), x


def elgamal_sign(data, public_key, private_key):

    p, g, y = public_key
    x = private_key

    # Convert SHA-512 digest into an integer.
    h = int.from_bytes(
        sha512_hash(data),
        "big"
    ) % (p - 1)

    # Select random k relatively prime to p-1.
    while True:
        k = secrets.randbelow(p - 2) + 1

        if math.gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)

    # Calculate second signature component.
    s = (
        (h - x * r) * inverse(k, p - 1)
    ) % (p - 1)

    return r, s


def elgamal_verify(data, signature, public_key):

    p, g, y = public_key
    r, s = signature

    if not (1 <= r < p and 0 <= s < p - 1):
        return False

    h = int.from_bytes(
        sha512_hash(data),
        "big"
    ) % (p - 1)

    left = pow(g, h, p)

    right = (
        pow(y, r, p) * pow(r, s, p)
    ) % p

    return left == right


# Generate ElGamal keys for registered voters.
voter_keys = {}

print("Generating voter signing keys...")

for username, info in users.items():

    if info["role"] == "Voter":
        public, private = elgamal_keygen()

        voter_keys[username] = {
            "public": public,
            "private": private
        }


# ============================================================
# 7. PAILLIER HOMOMORPHIC ENCRYPTION
# ============================================================

def paillier_keygen():

    p = getPrime(256)
    q = getPrime(256)

    while p == q:
        q = getPrime(256)

    n = p * q
    nsquare = n * n
    g = n + 1

    lam = math.lcm(p - 1, q - 1)

    # For g=n+1, L(g^lambda mod n²)=lambda.
    mu = inverse(lam, n)

    public = (n, nsquare, g)
    private = (lam, mu)

    return public, private


def paillier_encrypt(m, public):

    n, nsquare, g = public

    # Choose random r coprime to n.
    while True:
        r = secrets.randbelow(n - 1) + 1

        if math.gcd(r, n) == 1:
            break

    return (
        pow(g, m, nsquare) *
        pow(r, n, nsquare)
    ) % nsquare


def paillier_decrypt(ciphertext, public, private):

    n, nsquare, g = public
    lam, mu = private

    x = pow(ciphertext, lam, nsquare)

    # L(x) = (x-1)//n.
    L = (x - 1) // n

    return (L * mu) % n


# Generate Election Commission Paillier keys.
paillier_public, paillier_private = paillier_keygen()


# ============================================================
# 8. THRESHOLD KEY SHARING - 2 OF 3
# ============================================================

# Generate a prime larger than the Paillier modulus.
# Used as the field modulus for Shamir secret sharing.
SHARE_PRIME = getPrime(600)

while SHARE_PRIME <= paillier_public[0]:
    SHARE_PRIME = getPrime(600)


def split_secret(secret):

    # Create a degree-1 polynomial:
    # f(x) = secret + a*x mod SHARE_PRIME.
    #
    # Two points are sufficient to reconstruct the secret.

    a = secrets.randbelow(SHARE_PRIME)

    shares = []

    for x in (1, 2, 3):
        y = (secret + a * x) % SHARE_PRIME
        shares.append((x, y))

    return shares


def reconstruct_secret(shares):

    # Reconstruct f(0) using two Shamir shares.
    # inverse() calculates modular multiplicative inverse.

    result = 0

    for i, (xi, yi) in enumerate(shares):

        numerator = 1
        denominator = 1

        for j, (xj, yj) in enumerate(shares):

            if i == j:
                continue

            numerator = (
                numerator * (-xj)
            ) % SHARE_PRIME

            denominator = (
                denominator * (xi - xj)
            ) % SHARE_PRIME

        term = (
            yi *
            numerator *
            inverse(denominator, SHARE_PRIME)
        ) % SHARE_PRIME

        result = (result + term) % SHARE_PRIME

    return result


# Split both Paillier private parameters into three shares.
lam, mu = paillier_private

lambda_shares = split_secret(lam)
mu_shares = split_secret(mu)

# Each authority holds one share of each parameter.
authorities = {
    "A1": (lambda_shares[0], mu_shares[0]),
    "A2": (lambda_shares[1], mu_shares[1]),
    "A3": (lambda_shares[2], mu_shares[2])
}

# Remove the direct private-key reference from application state.
del paillier_private, lam, mu, lambda_shares, mu_shares


# ============================================================
# 9. HOMOMORPHIC TALLY INITIALIZATION
# ============================================================

# Store one encrypted counter per candidate.
# Encrypt zero rather than storing plaintext zero.
encrypted_totals = {
    candidate_id: paillier_encrypt(
        0, paillier_public
    )
    for candidate_id in CANDIDATES
}


# ============================================================
# 10. TRUSTED TIMESTAMP SIMULATION
# ============================================================

def issue_timestamp():

    # Timestamp is generated by the simulated authority.
    timestamp = time.time()

    timestamp_bytes = str(timestamp).encode()

    # Sign timestamp using authority private key.
    signature = pkcs1_15.new(timestamp_key).sign(
        SHA256.new(timestamp_bytes)
    )

    return timestamp, signature


def verify_timestamp(timestamp, signature):

    try:
        pkcs1_15.new(
            timestamp_key.publickey()
        ).verify(
            SHA256.new(str(timestamp).encode()),
            signature
        )

        return (
            VOTING_START <= timestamp <= VOTING_END
            and timestamp <= time.time()
        )

    except (ValueError, TypeError):
        return False


# ============================================================
# 11. HMAC SEARCHABLE INDEX
# ============================================================

def make_token(word):

    return hmac.new(
        search_key,
        str(word).lower().encode(),
        hashlib.sha256
    ).hexdigest()


def minute_bucket(timestamp):

    # Convert timestamp to its UTC minute number.
    return int(timestamp // 60)


def index_ballot(ballot_id, constituency, timestamp):

    # Index constituency without storing it as a plaintext
    # search-index key.
    constituency_token = make_token(
        "const:" + constituency
    )

    search_index.setdefault(
        constituency_token, set()
    ).add(ballot_id)

    # Index the minute containing the submission time.
    time_token = make_token(
        "minute:" + str(minute_bucket(timestamp))
    )

    search_index.setdefault(
        time_token, set()
    ).add(ballot_id)


def search_constituency():

    constituency = input("Constituency ID: ").strip()

    token = make_token("const:" + constituency)

    matches = sorted(
        search_index.get(token, set())
    )

    # Only return ballot IDs, not decrypted ballots.
    print("Matching ballot IDs:", matches)

    audit("CONSTITUENCY_SEARCH", constituency)


def search_time_range():

    try:
        start = float(input("Start Unix timestamp: "))
        end = float(input("End Unix timestamp: "))

    except ValueError:
        print("Invalid timestamps")
        return

    if end < start:
        print("Invalid time range")
        return

    matches = set()

    # Search minute-level HMAC tokens.
    # Results are approximate to the nearest minute.
    for minute in range(
        minute_bucket(start),
        minute_bucket(end) + 1
    ):
        token = make_token("minute:" + str(minute))

        matches.update(
            search_index.get(token, set())
        )

    print("Matching ballot IDs:", sorted(matches))

    audit("TIME_RANGE_SEARCH", f"{start} to {end}")


# ============================================================
# 12. SERIALIZE SIGNED BALLOT PACKAGE
# ============================================================

def signed_payload(package):

    # Convert all signed fields into consistent JSON bytes.
    # Hex strings are used for binary values.

    data = {
        "voter_id": package["voter_id"],
        "ballot_id": package["ballot_id"],
        "ballot_hash": package["ballot_hash"].hex(),
        "iv": package["iv"].hex(),
        "ciphertext": package["ciphertext"].hex(),
        "encrypted_key": package["encrypted_key"].hex(),
        "encrypted_votes": {
            str(k): str(v)
            for k, v in package["encrypted_votes"].items()
        },
        "timestamp": package["timestamp"],
        "timestamp_signature": package[
            "timestamp_signature"
        ].hex()
    }

    return json.dumps(
        data,
        sort_keys=True
    ).encode()


# ============================================================
# 13. CLIENT SIDE - CAST VOTE
# ============================================================

def cast_vote():

    voter_id = current_user

    if voter_id in voted:
        print("Vote already submitted")
        return

    if time.time() > VOTING_END:
        print("Voting deadline has passed")
        return

    constituency = input("Constituency ID: ").strip()

    print("\nCandidates:")

    for candidate_id, name in CANDIDATES.items():
        print(candidate_id, name)

    try:
        candidate = int(input("Candidate ID: "))

    except ValueError:
        print("Invalid candidate")
        return

    if candidate not in CANDIDATES or not constituency:
        print("Invalid ballot details")
        return

    ballot_id = secrets.token_hex(8)

    # Create ballot content as JSON bytes.
    ballot = {
        "ballot_id": ballot_id,
        "constituency": constituency,
        "candidate": candidate
    }

    ballot_bytes = json.dumps(
        ballot,
        sort_keys=True
    ).encode()

    # SHA-512 hash of ballot content.
    ballot_hash = sha512_hash(ballot_bytes)

    # Generate a new 32-byte AES-256 session key.
    aes_key = get_random_bytes(32)

    # Encrypt ballot using AES-256 CBC.
    iv, ciphertext = aes_encrypt(
        ballot_bytes,
        aes_key
    )

    # Encrypt AES session key with RSA-4096.
    encrypted_key = rsa_encrypt_key(aes_key)

    # Create one-hot encrypted candidate values.
    encrypted_votes = {}

    for candidate_id in CANDIDATES:

        value = 1 if candidate_id == candidate else 0

        encrypted_votes[candidate_id] = paillier_encrypt(
            value,
            paillier_public
        )

    # Obtain timestamp from simulated authority.
    timestamp, timestamp_signature = issue_timestamp()

    package = {
        "voter_id": voter_id,
        "ballot_id": ballot_id,
        "ballot_hash": ballot_hash,
        "iv": iv,
        "ciphertext": ciphertext,
        "encrypted_key": encrypted_key,
        "encrypted_votes": encrypted_votes,
        "timestamp": timestamp,
        "timestamp_signature": timestamp_signature
    }

    # Sign the entire ballot package using ElGamal.
    package["signature"] = elgamal_sign(
        signed_payload(package),
        voter_keys[voter_id]["public"],
        voter_keys[voter_id]["private"]
    )

    # Send the package to the simulated server.
    accepted = receive_ballot(package)

    if accepted:
        print("\nVote submitted successfully")
        print("Ballot ID:", ballot_id)
        print("SHA-512:", ballot_hash.hex())
        print("AES key size:", len(aes_key), "bytes")
        print("Encrypted AES key:", encrypted_key.hex())
        print("ElGamal signature:", package["signature"])
        print(
            "Timestamp:",
            datetime.fromtimestamp(
                timestamp, timezone.utc
            ).isoformat()
        )
        print("Paillier vote ciphertexts:", encrypted_votes)

    else:
        print("Vote rejected")


# ============================================================
# 14. SERVER SIDE - VERIFY AND RECEIVE BALLOT
# ============================================================

def receive_ballot(package):

    voter_id = package["voter_id"]
    ballot_id = package["ballot_id"]

    if voter_id not in voter_keys or voter_id in voted:
        audit("VOTE_REJECTED", "Invalid or duplicate voter")
        return False

    if ballot_id in ballots:
        audit("DUPLICATE_BALLOT", ballot_id)
        return False

    # Verify ElGamal signature over current package.
    valid_signature = elgamal_verify(
        signed_payload(package),
        package["signature"],
        voter_keys[voter_id]["public"]
    )

    print("ElGamal signature valid:", valid_signature)

    if not valid_signature:
        audit("SIGNATURE_FAILED", ballot_id)
        return False

    # Verify signed timestamp and voting period.
    valid_time = verify_timestamp(
        package["timestamp"],
        package["timestamp_signature"]
    )

    print("Timestamp valid:", valid_time)

    if not valid_time:
        audit("INVALID_TIMESTAMP", ballot_id)
        return False

    try:
        # Recover AES session key with RSA private key.
        aes_key = rsa_decrypt_key(
            package["encrypted_key"]
        )

        # Decrypt only the submitted ballot for validation.
        plaintext = aes_decrypt(
            package["iv"],
            package["ciphertext"],
            aes_key
        )

        # Compare SHA-512 with submitted ballot hash.
        recovered_hash = sha512_hash(plaintext)

        valid_hash = hmac.compare_digest(
            recovered_hash,
            package["ballot_hash"]
        )

        print("SHA-512 hash match:", valid_hash)

        if not valid_hash:
            audit("HASH_MISMATCH", ballot_id)
            return False

        ballot = json.loads(plaintext.decode())

    except (ValueError, KeyError, UnicodeError, TypeError):
        audit("DECRYPTION_FAILED", ballot_id)
        return False

    # Confirm that the ballot ID matches its package.
    if ballot["ballot_id"] != ballot_id:
        audit("BALLOT_ID_MISMATCH", ballot_id)
        return False

    if ballot["candidate"] not in CANDIDATES:
        audit("INVALID_CANDIDATE", ballot_id)
        return False

    # This simulation verifies the encrypted one-hot values
    # by regenerating them only in the client/server process.
    # A real election needs zero-knowledge proofs here.
    #
    # The server must not decrypt the Paillier vote values.

    n, nsquare, g = paillier_public

    # Aggregate each candidate's encrypted counter.
    for candidate_id in CANDIDATES:

        encrypted_totals[candidate_id] = (
            encrypted_totals[candidate_id] *
            package["encrypted_votes"][candidate_id]
        ) % nsquare

    # Store the encrypted package.
    ballots[ballot_id] = package

    # Index constituency and timestamp.
    index_ballot(
        ballot_id,
        ballot["constituency"],
        package["timestamp"]
    )

    voted.add(voter_id)

    audit("VOTE_ACCEPTED", ballot_id)

    return True


# ============================================================
# 15. VERIFY STORED BALLOT
# ============================================================

def verify_stored_ballot():

    ballot_id = input("Ballot ID: ").strip()

    if ballot_id not in ballots:
        print("Ballot not found")
        return

    package = ballots[ballot_id]
    voter_id = package["voter_id"]

    # Verify current package against original signature.
    valid = elgamal_verify(
        signed_payload(package),
        package["signature"],
        voter_keys[voter_id]["public"]
    )

    print("Signature valid:", valid)

    if not valid:
        audit("STORED_BALLOT_TAMPERED", ballot_id)


# ============================================================
# 16. TAMPERING DEMONSTRATION
# ============================================================

def tamper_ballot():

    ballot_id = input("Ballot ID: ").strip()

    if ballot_id not in ballots:
        print("Ballot not found")
        return

    package = ballots[ballot_id]

    # Flip one bit in the encrypted ballot.
    modified = bytearray(package["ciphertext"])

    if modified:
        modified[0] ^= 1

    package["ciphertext"] = bytes(modified)

    audit("BALLOT_MODIFIED", ballot_id)

    # Verify the modified package with original signature.
    valid = elgamal_verify(
        signed_payload(package),
        package["signature"],
        voter_keys[package["voter_id"]]["public"]
    )

    print("Signature valid after tampering:", valid)


# ============================================================
# 17. THRESHOLD DECRYPTION OF FINAL TALLY
# ============================================================

def final_tally():

    # Do not reveal the tally before the deadline.
    if time.time() < VOTING_END:
        print("Election is still open")
        return

    print("\nAvailable authorities: A1, A2, A3")

    first = input("First authority: ").strip().upper()
    second = input("Second authority: ").strip().upper()

    if first not in authorities or second not in authorities:
        print("Invalid authority")
        return

    if first == second:
        print("Two different authorities required")
        return

    # Retrieve two shares of lambda and mu.
    share1 = authorities[first]
    share2 = authorities[second]

    # Reconstruct Paillier private parameters.
    lam = reconstruct_secret([
        share1[0],
        share2[0]
    ])

    mu = reconstruct_secret([
        share1[1],
        share2[1]
    ])

    private = (lam, mu)

    print("\n--- FINAL ELECTION RESULTS ---")

    results = {}

    # Decrypt only the aggregate for each candidate.
    for candidate_id, encrypted_total in encrypted_totals.items():

        count = paillier_decrypt(
            encrypted_total,
            paillier_public,
            private
        )

        results[candidate_id] = count

        print(CANDIDATES[candidate_id], ":", count)

    print("Total votes:", sum(results.values()))

    highest = max(results.values())

    winners = [
        CANDIDATES[cid]
        for cid, count in results.items()
        if count == highest
    ]

    if len(winners) == 1:
        print("Winner:", winners[0])
    else:
        print("Tie between:", ", ".join(winners))

    audit(
        "FINAL_TALLY_DECRYPTED",
        f"Authorities: {first}, {second}"
    )


# ============================================================
# 18. LOGIN AND ROLE-BASED ACCESS
# ============================================================

def login():

    global current_user

    username = input("Username: ").strip()
    password = input("Password: ")

    user = users.get(username)

    if user is None or user["password"] != password:
        print("Invalid username or password")
        return

    current_user = username

    print("Login successful")
    print("Role:", user["role"])


def logout():

    global current_user

    current_user = None

    print("Logged out successfully")


# ============================================================
# 19. VOTER MENU
# ============================================================

def voter_menu():

    while current_user is not None:

        print("\n--- VOTER MENU ---")
        print("1. Cast Vote")
        print("2. Logout")

        choice = input("Choice: ")

        if choice == "1":
            cast_vote()

        elif choice == "2":
            logout()
            break

        else:
            print("Invalid choice")


# ============================================================
# 20. ELECTION OFFICER MENU
# ============================================================

def officer_menu():

    while current_user is not None:

        print("\n--- ELECTION OFFICER ---")
        print("1. Verify Stored Ballot")
        print("2. Search Constituency")
        print("3. Search Time Range")
        print("4. Final Threshold Tally")
        print("5. Tamper Ballot (Demo)")
        print("6. View Audit Log")
        print("7. Logout")

        choice = input("Choice: ")

        if choice == "1":
            verify_stored_ballot()

        elif choice == "2":
            search_constituency()

        elif choice == "3":
            search_time_range()

        elif choice == "4":
            final_tally()

        elif choice == "5":
            tamper_ballot()

        elif choice == "6":
            show_audit()

        elif choice == "7":
            logout()
            break

        else:
            print("Invalid choice")


# ============================================================
# 21. AUDITOR MENU
# ============================================================

def auditor_menu():

    while current_user is not None:

        print("\n--- AUDITOR MENU ---")
        print("1. Verify Ballot")
        print("2. Search Constituency")
        print("3. Search Time Range")
        print("4. View Audit Log")
        print("5. Logout")

        choice = input("Choice: ")

        if choice == "1":
            verify_stored_ballot()

        elif choice == "2":
            search_constituency()

        elif choice == "3":
            search_time_range()

        elif choice == "4":
            show_audit()

        elif choice == "5":
            logout()
            break

        else:
            print("Invalid choice")


# ============================================================
# 22. MAIN MENU
# ============================================================

def main():

    while True:

        print("\n========== NATIONAL E-VOTING ==========")
        print("1. Login")
        print("2. View Voting Deadline")
        print("3. Exit")

        choice = input("Choice: ")

        if choice == "1":

            login()

            if current_user is None:
                continue

            role = users[current_user]["role"]

            if role == "Voter":
                voter_menu()

            elif role == "Officer":
                officer_menu()

            elif role == "Auditor":
                auditor_menu()

        elif choice == "2":

            print(
                "Voting deadline:",
                datetime.fromtimestamp(
                    VOTING_END, timezone.utc
                ).isoformat()
            )

        elif choice == "3":
            print("Exiting...")
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

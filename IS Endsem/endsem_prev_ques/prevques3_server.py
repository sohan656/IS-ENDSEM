
import socket
import json
import time
import math
import hmac
import hashlib
import secrets
import threading

from datetime import datetime, timezone
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util.Padding import unpad
from Cryptodome.Util.number import getPrime, inverse


HOST = "127.0.0.1"
PORT = 5000

CANDIDATES = {
    1: "Candidate A",
    2: "Candidate B",
    3: "Candidate C"
}

# Voting period: 10 minutes after server starts
START_TIME = time.time()
END_TIME = START_TIME + 600

# Demo users; passwords are kept in a dictionary
users = {
    "v101": {"password": "1111", "role": "Voter"},
    "v102": {"password": "2222", "role": "Voter"},
    "v103": {"password": "3333", "role": "Voter"},
    "admin": {"password": "admin123", "role": "Admin"},
    "auditor": {"password": "audit123", "role": "Auditor"}
}

ballots = {}
voted = set()
search_index = {}
audit_log = []

# Server stores voter ElGamal public keys
voter_public_keys = {}

# Store authenticated session tokens
sessions = {}

search_key = secrets.token_bytes(32)

# Lock prevents simultaneous requests from modifying
# the voting data at the same time
lock = threading.RLock()


# ==================================================
# 1. AUDIT LOG
# ==================================================

def audit(action, details=""):
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "details": details
    }

    audit_log.append(entry)
    print("[AUDIT]", entry)


# ==================================================
# 2. RSA-4096 KEY GENERATION
# ==================================================

print("Generating RSA-4096 keys...")

rsa_key = RSA.generate(4096)

# Separate key for simulated timestamp signing
timestamp_key = RSA.generate(2048)


def decrypt_aes_key(encrypted_key):
    cipher = PKCS1_OAEP.new(
        rsa_key,
        hashAlgo=SHA256
    )

    return cipher.decrypt(bytes.fromhex(encrypted_key))


# ==================================================
# 3. AES-256 CBC DECRYPTION
# ==================================================

def aes_decrypt(iv, ciphertext, key):
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=bytes.fromhex(iv)
    )

    plaintext = cipher.decrypt(
        bytes.fromhex(ciphertext)
    )

    return unpad(plaintext, AES.block_size)


# ==================================================
# 4. SHA-512 HASHING
# ==================================================

def hash_ballot(data):
    return SHA512.new(data).hexdigest()


# ==================================================
# 5. ELGAMAL SIGNATURE VERIFICATION
# ==================================================

def verify_elgamal(data, signature, public):
    p, g, y = public
    r, s = signature

    if not (1 <= r < p and 0 <= s < p - 1):
        return False

    # Convert SHA-512 digest into an integer
    digest = SHA512.new(data).digest()
    h = int.from_bytes(digest, "big") % (p - 1)

    left = pow(g, h, p)

    right = (
        pow(y, r, p) * pow(r, s, p)
    ) % p

    return left == right


# ==================================================
# 6. PAILLIER KEY GENERATION
# ==================================================

def paillier_keygen():
    p = getPrime(256)
    q = getPrime(256)

    while p == q:
        q = getPrime(256)

    n = p * q
    ns = n * n

    lam = math.lcm(p - 1, q - 1)

    # g = n+1, so mu is inverse(lambda) modulo n
    mu = inverse(lam, n)

    return (n, ns, n + 1), (lam, mu)


def paillier_encrypt(m, public):
    n, ns, g = public

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

    return (((x - 1) // n) * mu) % n


paillier_public, private_key = paillier_keygen()

# Initialize encrypted counters with encrypted zero
encrypted_totals = {
    cid: paillier_encrypt(0, paillier_public)
    for cid in CANDIDATES
}


# ==================================================
# 7. SHAMIR SECRET SHARING (2 OF 3)
# ==================================================

# Prime modulus larger than Paillier's private lambda
SHARE_PRIME = getPrime(600)

while SHARE_PRIME <= private_key[0]:
    SHARE_PRIME = getPrime(600)


def split_secret(secret):
    # Polynomial: f(x) = secret + a*x
    a = secrets.randbelow(SHARE_PRIME)

    return [
        (x, (secret + a * x) % SHARE_PRIME)
        for x in (1, 2, 3)
    ]


def reconstruct_secret(shares):
    # Reconstruct a degree-1 polynomial at x=0
    (x1, y1), (x2, y2) = shares

    numerator = (
        y1 * x2 - y2 * x1
    ) % SHARE_PRIME

    denominator = (
        x2 - x1
    ) % SHARE_PRIME

    return (
        numerator * inverse(denominator, SHARE_PRIME)
    ) % SHARE_PRIME


# Only lambda needs sharing because mu can be
# recalculated from lambda for g=n+1
shares = split_secret(private_key[0])

authorities = {
    "A1": shares[0],
    "A2": shares[1],
    "A3": shares[2]
}

del private_key, shares


# ==================================================
# 8. TRUSTED TIMESTAMP SIMULATION
# ==================================================

def issue_timestamp():
    timestamp = time.time()

    # Sign the timestamp using the authority's RSA key
    signature = pkcs1_15.new(
        timestamp_key
    ).sign(
        SHA256.new(str(timestamp).encode())
    )

    return timestamp, signature.hex()


def verify_timestamp(timestamp, signature):
    try:
        pkcs1_15.new(
            timestamp_key.publickey()
        ).verify(
            SHA256.new(str(timestamp).encode()),
            bytes.fromhex(signature)
        )

        return START_TIME <= timestamp <= END_TIME

    except (ValueError, TypeError):
        return False


# ==================================================
# 9. HMAC SEARCHABLE INDEX
# ==================================================

def make_token(word):
    return hmac.new(
        search_key,
        str(word).lower().encode(),
        hashlib.sha256
    ).hexdigest()


def add_to_index(ballot_id, constituency, timestamp):
    # Index the constituency
    token = make_token("const:" + constituency)

    search_index.setdefault(
        token, set()
    ).add(ballot_id)

    # Index submission minute
    minute = int(timestamp // 60)
    token = make_token(f"time:{minute}")

    search_index.setdefault(
        token, set()
    ).add(ballot_id)


def search_constituency(constituency):
    token = make_token("const:" + constituency)

    return sorted(
        search_index.get(token, set())
    )


def search_time_range(start, end):
    if end < start:
        return []

    matches = set()

    # Search minute buckets within the given range
    for minute in range(
        int(start // 60),
        int(end // 60) + 1
    ):
        token = make_token(f"time:{minute}")

        matches.update(
            search_index.get(token, set())
        )

    return sorted(matches)


# ==================================================
# 10. CREATE CONSISTENT SIGNED DATA
# ==================================================

def signed_data(packet):
    # Exclude signature from the data being verified
    data = {
        key: value
        for key, value in packet.items()
        if key != "signature"
    }

    return json.dumps(
        data,
        sort_keys=True
    ).encode()


# ==================================================
# 11. RECEIVE AND VERIFY BALLOT
# ==================================================

def receive_ballot(username, packet):
    with lock:
        if username in voted:
            audit("DUPLICATE_VOTE", username)
            return {"error": "Voter already voted"}

        if time.time() > END_TIME:
            return {"error": "Voting deadline passed"}

        if username not in voter_public_keys:
            return {"error": "Voter public key not registered"}

        if packet.get("voter_id") != username:
            return {"error": "Voter ID mismatch"}

        # Verify ElGamal signature
        try:
            signature = tuple(
                int(x) for x in packet["signature"]
            )

            valid = verify_elgamal(
                signed_data(packet),
                signature,
                voter_public_keys[username]
            )

        except (ValueError, KeyError, TypeError):
            valid = False

        print("ElGamal signature valid:", valid)

        if not valid:
            audit("SIGNATURE_FAILED", username)
            return {"error": "Invalid signature"}

        # Timestamp is issued at server receipt
        timestamp, timestamp_signature = issue_timestamp()

        valid_time = verify_timestamp(
            timestamp,
            timestamp_signature
        )

        print("Timestamp valid:", valid_time)

        if not valid_time:
            return {"error": "Invalid timestamp"}

        try:
            # Decrypt the AES session key using RSA-4096
            aes_key = decrypt_aes_key(
                packet["encrypted_key"]
            )

            # Decrypt the AES-encrypted ballot
            plaintext = aes_decrypt(
                packet["iv"],
                packet["ciphertext"],
                aes_key
            )

            # Compare SHA-512 hashes
            recovered_hash = hash_ballot(plaintext)

            hash_valid = hmac.compare_digest(
                recovered_hash,
                packet["ballot_hash"]
            )

            print("SHA-512 hash match:", hash_valid)

            if not hash_valid:
                audit("HASH_FAILED", username)
                return {"error": "Hash mismatch"}

            ballot = json.loads(plaintext.decode())

            candidate = int(ballot["candidate"])
            constituency = ballot["constituency"]
            ballot_id = ballot["ballot_id"]

            if candidate not in CANDIDATES:
                return {"error": "Invalid candidate"}

            if not constituency:
                return {"error": "Invalid constituency"}

            if ballot_id != packet["ballot_id"]:
                return {"error": "Ballot ID mismatch"}

            if ballot_id in ballots:
                return {"error": "Duplicate ballot ID"}

            # Read encrypted one-hot vote components
            encrypted_votes = {
                int(k): int(v)
                for k, v in packet["encrypted_votes"].items()
            }

            if set(encrypted_votes) != set(CANDIDATES):
                return {"error": "Invalid encrypted vote fields"}

            n, ns, g = paillier_public

            if any(
                not (1 <= c < ns and math.gcd(c, n) == 1)
                for c in encrypted_votes.values()
            ):
                return {"error": "Invalid Paillier ciphertext"}

        except (
            ValueError, KeyError, TypeError,
            UnicodeError, OverflowError
        ):
            audit("BALLOT_REJECTED", username)
            return {"error": "Invalid ballot data"}

        # Multiply encrypted counters for each candidate
        n, ns, g = paillier_public

        for cid in CANDIDATES:
            encrypted_totals[cid] = (
                encrypted_totals[cid] *
                encrypted_votes[cid]
            ) % ns

        # Store only encrypted ballot package
        stored_packet = dict(packet)

        stored_packet["timestamp"] = timestamp
        stored_packet["timestamp_signature"] = timestamp_signature

        ballots[ballot_id] = stored_packet

        add_to_index(
            ballot_id,
            constituency,
            timestamp
        )

        voted.add(username)

        audit("VOTE_ACCEPTED", ballot_id)

        return {
            "success": True,
            "ballot_id": ballot_id,
            "signature_valid": True,
            "hash_valid": True,
            "timestamp_valid": True,
            "timestamp": timestamp,
            "timestamp_signature": timestamp_signature
        }


# ==================================================
# 12. VERIFY STORED BALLOT
# ==================================================

def verify_stored_ballot(ballot_id):
    packet = ballots.get(ballot_id)

    if packet is None:
        return {"error": "Ballot not found"}

    voter_id = packet["voter_id"]

    # Remove server-added timestamp fields before verifying
    original = {
        k: v for k, v in packet.items()
        if k not in ("timestamp", "timestamp_signature")
    }

    try:
        valid = verify_elgamal(
            signed_data(original),
            tuple(int(x) for x in packet["signature"]),
            voter_public_keys[voter_id]
        )

    except (ValueError, KeyError, TypeError):
        valid = False

    if not valid:
        audit("BALLOT_TAMPERING_DETECTED", ballot_id)

    return {"signature_valid": valid}


# ==================================================
# 13. FINAL THRESHOLD TALLY
# ==================================================

def final_tally(first, second):
    if time.time() < END_TIME:
        return {"error": "Election still open"}

    if first == second:
        return {"error": "Choose two different authorities"}

    if first not in authorities or second not in authorities:
        return {"error": "Invalid authority"}

    # Reconstruct lambda using two authority shares
    lam = reconstruct_secret([
        authorities[first],
        authorities[second]
    ])

    n, ns, g = paillier_public

    # Recalculate mu using reconstructed lambda
    mu = inverse(lam, n)

    private = (lam, mu)

    results = {}

    # Decrypt aggregate only, not individual votes
    for cid, encrypted_total in encrypted_totals.items():
        results[str(cid)] = paillier_decrypt(
            encrypted_total,
            paillier_public,
            private
        )

    audit(
        "FINAL_TALLY",
        f"Authorities {first} and {second}"
    )

    return {
        "success": True,
        "results": results,
        "total_votes": sum(results.values())
    }


# ==================================================
# 14. LOGIN AND SESSION HANDLING
# ==================================================

def login(username, password):
    username = username.strip().lower()

    user = users.get(username)

    if user is None or user["password"] != password:
        audit("LOGIN_FAILED", username)
        return {"error": "Invalid username or password"}

    # Generate random session token after successful login
    token = secrets.token_hex(32)

    sessions[token] = username

    audit("LOGIN_SUCCESS", username)

    return {
        "success": True,
        "token": token,
        "role": user["role"],
        "username": username
    }


def authenticated_user(request):
    token = request.get("token", "")
    return sessions.get(token)


# ==================================================
# 15. REQUEST HANDLER
# ==================================================

def handle_request(request):
    action = request.get("action")

    if action == "login":
        return login(
            request.get("username", ""),
            request.get("password", "")
        )

    if action == "public_keys":
        return {
            "rsa_public": rsa_key.publickey().export_key().decode(),
            "paillier_public": [
                str(x) for x in paillier_public
            ],
            "candidates": CANDIDATES,
            "deadline": END_TIME
        }

    username = authenticated_user(request)

    if username is None:
        return {"error": "Login required"}

    role = users[username]["role"]

    if action == "logout":
        sessions.pop(request.get("token"), None)
        return {"success": True}

    if action == "register_key" and role == "Voter":
        if username in voter_public_keys:
            return {"error": "Public key already registered"}

        try:
            public = tuple(
                int(x) for x in request["public_key"]
            )

            p, g, y = public

            if not (
                p > 3 and
                1 < g < p and
                1 <= y < p
            ):
                return {"error": "Invalid public key"}

        except (ValueError, KeyError, TypeError):
            return {"error": "Invalid public key"}

        voter_public_keys[username] = public

        audit("PUBLIC_KEY_REGISTERED", username)

        return {"success": True}

    if action == "vote" and role == "Voter":
        return receive_ballot(
            username,
            request.get("packet", {})
        )

    if action == "verify" and role in ("Admin", "Auditor"):
        return verify_stored_ballot(
            request.get("ballot_id", "")
        )

    if action == "search" and role in ("Admin", "Auditor"):
        constituency = request.get("constituency", "")

        return {
            "matches": search_constituency(constituency)
        }

    if action == "search_time" and role in ("Admin", "Auditor"):
        try:
            start = float(request["start"])
            end = float(request["end"])

            return {
                "matches": search_time_range(start, end)
            }

        except (ValueError, KeyError):
            return {"error": "Invalid time range"}

    if action == "audit" and role in ("Admin", "Auditor"):
        return {"audit_log": audit_log}

    if action == "tally" and role == "Admin":
        return final_tally(
            request.get("first", ""),
            request.get("second", "")
        )

    if action == "tamper" and role == "Admin":
        ballot_id = request.get("ballot_id", "")

        if ballot_id not in ballots:
            return {"error": "Ballot not found"}

        packet = ballots[ballot_id]

        ct = bytearray.fromhex(packet["ciphertext"])

        if ct:
            ct[0] ^= 1
            packet["ciphertext"] = ct.hex()

        audit("BALLOT_TAMPERED", ballot_id)

        return verify_stored_ballot(ballot_id)

    return {"error": "Permission denied or invalid action"}


# ==================================================
# 16. SOCKET SERVER
# ==================================================

def client_handler(connection):
    try:
        # Each request is one JSON line
        with connection.makefile("rwb") as stream:

            for line in stream:
                try:
                    request = json.loads(line.decode())

                    response = handle_request(request)

                except Exception as e:
                    response = {
                        "error": f"Request failed: {type(e).__name__}"
                    }

                stream.write(
                    (json.dumps(response) + "\n").encode()
                )

                stream.flush()

    finally:
        connection.close()


def main():
    print("\nElection server started")
    print("Voting deadline:", datetime.fromtimestamp(
        END_TIME, timezone.utc
    ).isoformat())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind((HOST, PORT))
        server.listen(5)

        print(f"Listening on {HOST}:{PORT}")

        while True:
            connection, address = server.accept()

            print("Client connected:", address)

            thread = threading.Thread(
                target=client_handler,
                args=(connection,),
                daemon=True
            )

            thread.start()


if __name__ == "__main__":
    main()

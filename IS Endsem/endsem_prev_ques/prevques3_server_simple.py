
import socket
import json
import time
import math
import hmac
import hashlib
import secrets

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.Util.Padding import unpad
from Cryptodome.Util.number import getPrime, inverse


HOST = "127.0.0.1"
PORT = 5050

# Three candidates and predefined user accounts
candidates = {1: "A", 2: "B", 3: "C"}

users = {
    "v101": ("1111", "Voter"),
    "v102": ("2222", "Voter"),
    "v103": ("3333", "Voter"),
    "admin": ("admin123", "Admin"),
    "auditor": ("audit123", "Auditor")
}

deadline = time.time() + 600  # Voting open for 10 minutes

ballots = {}
voted = set()
index = {}
audit_log = []

search_key = secrets.token_bytes(32)

print("Generating RSA-4096 key...")
rsa_key = RSA.generate(4096)


# --------------------------------------------------
# 1. PAILLIER KEY GENERATION AND DECRYPTION
# --------------------------------------------------

def paillier_keys():
    p, q = getPrime(256), getPrime(256)

    while p == q:
        q = getPrime(256)

    n = p * q
    lam = math.lcm(p - 1, q - 1)
    mu = inverse(lam, n)

    return (n, n*n, n+1), (lam, mu)


def paillier_decrypt(c, private):
    lam, mu = private
    n, ns, g = paillier_public

    return (((pow(c, lam, ns) - 1) // n) * mu) % n


paillier_public, private_key = paillier_keys()

# Encrypted counters initially contain 1 = encryption of zero
# using r=1; for demonstration only.
totals = {cid: 1 for cid in candidates}


# --------------------------------------------------
# 2. SIMPLIFIED 2-OF-3 KEY SHARING
# --------------------------------------------------

# Create a prime greater than the private lambda value
P = getPrime(600)

while P <= private_key[0]:
    P = getPrime(600)


def split_secret(secret):
    a = secrets.randbelow(P)

    return [
        (x, (secret + a*x) % P)
        for x in (1, 2, 3)
    ]


def recover_secret(s1, s2):
    x1, y1 = s1
    x2, y2 = s2

    return (
        (y1*x2 - y2*x1) *
        inverse(x2-x1, P)
    ) % P


shares = split_secret(private_key[0])
del private_key

# All shares are kept by the server in this lab simulation.


# --------------------------------------------------
# 3. HMAC SEARCH INDEX
# --------------------------------------------------

def token(word):
    return hmac.new(
        search_key,
        word.lower().encode(),
        hashlib.sha256
    ).hexdigest()


def add_index(ballot_id, constituency, timestamp):
    for word in [
        constituency,
        str(int(timestamp // 60))
    ]:
        index.setdefault(token(word), set()).add(ballot_id)


# --------------------------------------------------
# 4. ELGAMAL SIGNATURE VERIFICATION
# --------------------------------------------------

def verify_elgamal(data, signature, public):
    p, g, y = public
    r, s = signature

    h = int.from_bytes(
        SHA512.new(data).digest(), "big"
    ) % (p-1)

    return (
        1 <= r < p
        and 0 <= s < p-1
        and pow(g, h, p) ==
        (pow(y, r, p) * pow(r, s, p)) % p
    )


# --------------------------------------------------
# 5. VERIFY AND STORE VOTE
# --------------------------------------------------

def receive_vote(packet, voter_id, public_key):
    if voter_id in voted or time.time() > deadline:
        return {"error": "Duplicate vote or deadline passed"}

    # Signatures cover the packet without the signature field
    signed = {
        k: v for k, v in packet.items()
        if k != "signature"
    }

    data = json.dumps(signed, sort_keys=True).encode()

    signature = [int(x) for x in packet["signature"]]

    if not verify_elgamal(data, signature, public_key):
        return {"error": "Invalid ElGamal signature"}

    try:
        # RSA-OAEP decrypts the AES session key
        aes_key = PKCS1_OAEP.new(
            rsa_key, hashAlgo=SHA256
        ).decrypt(bytes.fromhex(packet["encrypted_key"]))

        # AES-256 CBC decrypts the ballot
        cipher = AES.new(
            aes_key, AES.MODE_CBC,
            iv=bytes.fromhex(packet["iv"])
        )

        ballot_bytes = unpad(
            cipher.decrypt(bytes.fromhex(packet["ciphertext"])),
            AES.block_size
        )

        # Compare SHA-512 hashes
        calculated_hash = SHA512.new(ballot_bytes).hexdigest()

        if not hmac.compare_digest(
            calculated_hash, packet["hash"]
        ):
            return {"error": "SHA-512 hash mismatch"}

        ballot = json.loads(ballot_bytes.decode())
        candidate = int(ballot["candidate"])
        constituency = ballot["constituency"]

        if candidate not in candidates:
            return {"error": "Invalid candidate"}

        encrypted_votes = {
            int(k): int(v)
            for k, v in packet["encrypted_votes"].items()
        }

        if set(encrypted_votes) != set(candidates):
            return {"error": "Invalid encrypted vote fields"}

        n, ns, g = paillier_public

        if any(
            not (1 <= c < ns and math.gcd(c, n) == 1)
            for c in encrypted_votes.values()
        ):
            return {"error": "Invalid Paillier ciphertext"}

    except (ValueError, KeyError, TypeError):
        return {"error": "Invalid encrypted ballot"}

    ballot_id = packet["ballot_id"]

    if ballot_id in ballots:
        return {"error": "Duplicate ballot ID"}

    # Multiply ciphertexts to add encrypted vote counters
    for cid in candidates:
        totals[cid] = (
            totals[cid] * encrypted_votes[cid]
        ) % paillier_public[1]

    timestamp = time.time()

    ballots[ballot_id] = packet
    voted.add(voter_id)

    add_index(ballot_id, constituency, timestamp)

    audit_log.append(("VOTE_ACCEPTED", voter_id, timestamp))

    return {
        "success": True,
        "ballot_id": ballot_id,
        "signature_valid": True,
        "hash_valid": True,
        "timestamp": timestamp
    }


# --------------------------------------------------
# 6. SERVER REQUEST HANDLER
# --------------------------------------------------

def handle(request):
    action = request.get("action")

    if action == "keys":
        return {
            "rsa": rsa_key.publickey().export_key().decode(),
            "paillier": [str(x) for x in paillier_public]
        }

    username = request.get("username", "").lower()
    password = request.get("password", "")

    if username not in users or users[username][0] != password:
        return {"error": "Invalid login"}

    role = users[username][1]

    if action == "vote" and role == "Voter":
        public = tuple(int(x) for x in request["public_key"])

        return receive_vote(
            request["packet"], username, public
        )

    if action == "search" and role in ("Admin", "Auditor"):
        word = request.get("keyword", "").lower()

        return {
            "matches": sorted(index.get(token(word), set()))
        }

    if action == "audit" and role in ("Admin", "Auditor"):
        return {"audit": audit_log}

    if action == "tally" and role == "Admin":
        if time.time() < deadline:
            return {"error": "Election still open"}

        # Reconstruct lambda from the first two shares
        lam = recover_secret(shares[0], shares[1])

        # mu = inverse(lambda, n) for g=n+1
        private = (lam, inverse(lam, paillier_public[0]))

        return {
            "results": {
                str(cid): paillier_decrypt(c, private)
                for cid, c in totals.items()
            }
        }

    return {"error": "Access denied"}


# --------------------------------------------------
# 7. SOCKET SERVER
# --------------------------------------------------

def main():
    print("Server running on port", PORT)

    with socket.socket() as server:
        server.bind((HOST, PORT))
        server.listen(5)

        while True:
            conn, addr = server.accept()

            with conn:
                # Receive one JSON request per connection
                data = b""

                while not data.endswith(b"\n"):
                    chunk = conn.recv(4096)

                    if not chunk:
                        break

                    data += chunk

                try:
                    request = json.loads(data.decode())
                    response = handle(request)

                except Exception as e:
                    response = {"error": str(e)}

                conn.sendall(
                    (json.dumps(response) + "\n").encode()
                )


if __name__ == "__main__":
    main()


import socket
import json
import math
import secrets

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
from Cryptodome.Util.number import getPrime, isPrime, inverse


HOST = "127.0.0.1"
PORT = 5050


# --------------------------------------------------
# 1. SOCKET COMMUNICATION
# --------------------------------------------------

def send(request):
    with socket.create_connection((HOST, PORT)) as sock:
        sock.sendall(
            (json.dumps(request) + "\n").encode()
        )

        data = b""

        while not data.endswith(b"\n"):
            chunk = sock.recv(4096)

            if not chunk:
                break

            data += chunk

    return json.loads(data.decode())


# --------------------------------------------------
# 2. ELGAMAL SIGNATURE
# --------------------------------------------------

def elgamal_keys():
    q = getPrime(256)
    p = 2*q + 1

    while not isPrime(p):
        q = getPrime(256)
        p = 2*q + 1

    while True:
        g = secrets.randbelow(p-3) + 2

        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            break

    x = secrets.randbelow(p-2) + 1
    y = pow(g, x, p)

    return (p, g, y), x


def elgamal_sign(data, public, private):
    p, g, y = public

    h = int.from_bytes(
        SHA512.new(data).digest(), "big"
    ) % (p-1)

    while True:
        k = secrets.randbelow(p-2) + 1

        if math.gcd(k, p-1) == 1:
            break

    r = pow(g, k, p)

    s = (
        (h - private*r) * inverse(k, p-1)
    ) % (p-1)

    return [str(r), str(s)]


# --------------------------------------------------
# 3. PAILLIER ENCRYPTION
# --------------------------------------------------

def paillier_encrypt(m, public):
    n, ns, g = public

    while True:
        r = secrets.randbelow(n-1) + 1

        if math.gcd(r, n) == 1:
            break

    return (
        pow(g, m, ns) * pow(r, n, ns)
    ) % ns


# --------------------------------------------------
# 4. CAST VOTE
# --------------------------------------------------

def cast_vote(username, password, rsa_public, paillier_public):
    constituency = input("Constituency ID: ").strip()
    candidate = int(input("Candidate (1/2/3): "))

    if candidate not in (1, 2, 3) or not constituency:
        print("Invalid ballot")
        return

    ballot_id = secrets.token_hex(8)

    ballot = {
        "candidate": candidate,
        "constituency": constituency
    }

    ballot_bytes = json.dumps(
        ballot, sort_keys=True
    ).encode()

    # SHA-512 hash of ballot
    ballot_hash = SHA512.new(ballot_bytes).hexdigest()

    # Generate 32-byte AES-256 key
    aes_key = get_random_bytes(32)

    # AES-256 CBC encryption
    cipher = AES.new(aes_key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(ballot_bytes, AES.block_size)
    )

    # RSA-4096 encrypts AES session key
    encrypted_key = PKCS1_OAEP.new(
        rsa_public, hashAlgo=SHA256
    ).encrypt(aes_key)

    # Encrypt one-hot votes using Paillier
    encrypted_votes = {
        str(cid): str(
            paillier_encrypt(
                1 if cid == candidate else 0,
                paillier_public
            )
        )
        for cid in (1, 2, 3)
    }

    # Generate voter ElGamal key pair
    public, private = elgamal_keys()

    packet = {
        "ballot_id": ballot_id,
        "hash": ballot_hash,
        "iv": cipher.iv.hex(),
        "ciphertext": ciphertext.hex(),
        "encrypted_key": encrypted_key.hex(),
        "encrypted_votes": encrypted_votes
    }

    # Sign all packet fields
    signed_data = json.dumps(
        packet, sort_keys=True
    ).encode()

    packet["signature"] = elgamal_sign(
        signed_data, public, private
    )

    response = send({
        "action": "vote",
        "username": username,
        "password": password,
        "public_key": [str(x) for x in public],
        "packet": packet
    })

    print("\nSHA-512:", ballot_hash)
    print("AES ciphertext:", ciphertext.hex())
    print("RSA encrypted AES key:", encrypted_key.hex())
    print("ElGamal signature:", packet["signature"])
    print("Paillier encrypted votes:", encrypted_votes)
    print("Server response:", response)


# --------------------------------------------------
# 5. MAIN MENU
# --------------------------------------------------

def main():
    username = input("Username: ").strip().lower()
    password = input("Password: ")

    key_data = send({"action": "keys"})

    rsa_public = RSA.import_key(key_data["rsa"])

    paillier_public = tuple(
        int(x) for x in key_data["paillier"]
    )

    while True:
        print("\n--- E-VOTING CLIENT ---")
        print("1. Cast Vote")
        print("2. Search Ballots")
        print("3. View Audit Log")
        print("4. Final Tally")
        print("5. Exit")

        choice = input("Choice: ")

        if choice == "1":
            cast_vote(
                username, password,
                rsa_public, paillier_public
            )

        elif choice == "2":
            keyword = input(
                "Constituency or minute bucket: "
            )

            print(send({
                "action": "search",
                "username": username,
                "password": password,
                "keyword": keyword
            }))

        elif choice == "3":
            print(send({
                "action": "audit",
                "username": username,
                "password": password
            }))

        elif choice == "4":
            print(send({
                "action": "tally",
                "username": username,
                "password": password
            }))

        elif choice == "5":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

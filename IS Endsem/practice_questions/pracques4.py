'''
Question 4: Privacy-Preserving Electronic Voting System
20 marks
An election authority wants to develop a secure voting system where individual votes remain confidential while the total votes for each candidate can be calculated.

There are two candidates, A and B, and five registered voters.

Requirements:
1. Paillier Encryption (5 marks): Encrypt votes and calculate totals without decrypting individual votes.
2. RSA Digital Signatures (4 marks): Digitally sign vote submissions and verify authenticity.
3. SHA-256 Integrity (3 marks): Detect whether an encrypted vote has been modified.
4. Duplicate Vote Prevention (3 marks): Ensure each voter submits only one vote.
5. Integration and Documentation (5 marks): Create a menu-driven application and display the final results.
'''


import math
import secrets
import hashlib

from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util.number import getPrime, inverse


# ------------------------------------------
# 1. PAILLIER KEY GENERATION
# ------------------------------------------

def keygen():
    p = getPrime(256)
    q = getPrime(256)

    while p == q:
        q = getPrime(256)

    n = p * q
    ns = n * n

    lam = math.lcm(p - 1, q - 1)
    mu = inverse(lam, n)

    return (n, ns), (lam, mu)


def encrypt_vote(m, public):
    n, ns = public

    r = secrets.randbelow(n - 1) + 1

    while math.gcd(r, n) != 1:
        r = secrets.randbelow(n - 1) + 1

    return (
        pow(n + 1, m, ns) *
        pow(r, n, ns)
    ) % ns


def decrypt_total(c, public, private):
    n, ns = public
    lam, mu = private

    x = pow(c, lam, ns)
    return (((x - 1) // n) * mu) % n


# ------------------------------------------
# 2. REGISTER VOTERS
# ------------------------------------------

voters = {
    "V101": RSA.generate(2048),
    "V102": RSA.generate(2048),
    "V103": RSA.generate(2048),
    "V104": RSA.generate(2048),
    "V105": RSA.generate(2048)
}

public, private = keygen()

voted = set()
ballots = []

# Encrypted zero for each candidate
total_A = encrypt_vote(0, public)
total_B = encrypt_vote(0, public)


# ------------------------------------------
# 3. DIGITAL SIGNATURE
# ------------------------------------------

def sign_vote(voter_id, ciphertext):
    message = f"{voter_id}|{ciphertext}"

    return pkcs1_15.new(voters[voter_id]).sign(
        SHA256.new(message.encode())
    )


def verify_vote(voter_id, ciphertext, signature):
    message = f"{voter_id}|{ciphertext}"

    try:
        pkcs1_15.new(
            voters[voter_id].publickey()
        ).verify(
            SHA256.new(message.encode()),
            signature
        )
        return True

    except (ValueError, TypeError):
        return False


# ------------------------------------------
# 4. CAST VOTE
# ------------------------------------------

def cast_vote():
    global total_A, total_B

    voter_id = input("Voter ID: ").upper()

    if voter_id not in voters:
        print("Unregistered voter")
        return

    if voter_id in voted:
        print("Duplicate vote rejected")
        return

    choice = input("Candidate (A/B): ").upper()

    if choice not in ["A", "B"]:
        print("Invalid candidate")
        return

    # One-hot vote representation
    vote_a = 1 if choice == "A" else 0
    vote_b = 1 if choice == "B" else 0

    c_a = encrypt_vote(vote_a, public)
    c_b = encrypt_vote(vote_b, public)

    # Sign both encrypted vote components
    combined = f"{c_a}|{c_b}"
    signature = sign_vote(voter_id, combined)

    if not verify_vote(voter_id, combined, signature):
        print("Invalid signature")
        return

    # Hash of encrypted ballot
    ballot_hash = hashlib.sha256(
        combined.encode()
    ).hexdigest()

    n, ns = public

    total_A = (total_A * c_a) % ns
    total_B = (total_B * c_b) % ns

    ballots.append({
        "voter": voter_id,
        "ciphertext": combined,
        "signature": signature,
        "hash": ballot_hash
    })

    voted.add(voter_id)

    print("Encrypted vote accepted")


# ------------------------------------------
# 5. VERIFY BALLOT INTEGRITY
# ------------------------------------------

def verify_ballots():
    for ballot in ballots:
        current_hash = hashlib.sha256(
            ballot["ciphertext"].encode()
        ).hexdigest()

        hash_ok = current_hash == ballot["hash"]

        signature_ok = verify_vote(
            ballot["voter"],
            ballot["ciphertext"],
            ballot["signature"]
        )

        print(
            ballot["voter"],
            "VALID" if hash_ok and signature_ok else "INVALID"
        )


# ------------------------------------------
# 6. HOMOMORPHIC VOTE COUNTING
# ------------------------------------------

def show_results():
    a = decrypt_total(total_A, public, private)
    b = decrypt_total(total_B, public, private)

    print("\nCandidate A:", a)
    print("Candidate B:", b)
    print("Total votes:", a + b)

    if a > b:
        print("Winner: Candidate A")
    elif b > a:
        print("Winner: Candidate B")
    else:
        print("Election tied")


# ------------------------------------------
# 7. MAIN MENU
# ------------------------------------------

def main():
    while True:
        print("\n--- SECURE VOTING SYSTEM ---")
        print("1. Cast Vote")
        print("2. Verify Ballots")
        print("3. Display Results")
        print("4. Exit")

        choice = input("Choice: ")

        if choice == "1":
            cast_vote()

        elif choice == "2":
            verify_ballots()

        elif choice == "3":
            show_results()

        elif choice == "4":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

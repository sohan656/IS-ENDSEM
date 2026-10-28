import secrets
from Cryptodome.Util.number import getPrime, isPrime


# ==================================================
# 1. GENERATE DH PARAMETERS
# ==================================================

def generate_parameters():

    # Generate a safe prime p = 2q + 1
    q = getPrime(256)
    p = 2 * q + 1

    while not isPrime(p):
        q = getPrime(256)
        p = 2 * q + 1

    g = 4  # Generator of a subgroup of order q

    return p, g, q


# ==================================================
# 2. GENERATE PRIVATE AND PUBLIC KEYS
# ==================================================

def generate_keys(p, g, q):

    # Generate random private key between 1 and q-1
    private = secrets.randbelow(q - 1) + 1

    # Public key = g^private mod p
    public = pow(g, private, p)

    return private, public


# ==================================================
# 3. GENERATE SHARED SECRET
# ==================================================

def generate_shared_secret(other_public, private, p):

    # Shared secret = other party's public key ^ private mod p
    return pow(other_public, private, p)


# ==================================================
# 4. DIFFIE-HELLMAN KEY EXCHANGE
# ==================================================

def diffie_hellman():

    p, g, q = generate_parameters()

    # Alice generates her private and public keys
    alice_private, alice_public = generate_keys(p, g, q)

    # Bob generates his private and public keys
    bob_private, bob_public = generate_keys(p, g, q)

    print("\nPublic Prime (p):", p)
    print("Generator (g):", g)

    print("\nAlice Public Key:", alice_public)
    print("Bob Public Key:", bob_public)

    # Alice calculates shared secret using Bob's public key
    alice_shared = generate_shared_secret(
        bob_public, alice_private, p
    )

    # Bob calculates shared secret using Alice's public key
    bob_shared = generate_shared_secret(
        alice_public, bob_private, p
    )

    print("\nAlice Shared Secret:", alice_shared)
    print("Bob Shared Secret:", bob_shared)

    if alice_shared == bob_shared:
        print("\nKEY EXCHANGE VERIFIED")
    else:
        print("\nKEY EXCHANGE FAILED")


# ==================================================
# 5. MAIN MENU
# ==================================================

def main():

    while True:
        print("\n===== DIFFIE-HELLMAN =====")
        print("1. Perform Key Exchange")
        print("2. Exit")

        choice = input("Choice: ")

        if choice == "1":
            diffie_hellman()

        elif choice == "2":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

from Cryptodome.PublicKey import ECC
from Cryptodome.Protocol.DH import key_agreement
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256


# ==================================================
# 1. GENERATE ECC KEYS
# ==================================================

def generate_ecc_keys():

    # Generate ECC private key using the P-256 curve
    private_key = ECC.generate(curve="P-256")

    # Extract the corresponding public key
    public_key = private_key.public_key()

    return private_key, public_key


# ==================================================
# 2. DERIVE SHARED KEY USING ECDH
# ==================================================

def generate_shared_key(private_key, other_public_key):

    # Derive a 32-byte AES-256 key from the shared secret
    def kdf(shared_secret):
        return HKDF(
            shared_secret,
            32,                  # 32 bytes for AES-256
            b"ECDH-Salt",        # HKDF salt
            SHA256
        )

    # Combine own private key with other party's public key
    return key_agreement(
        static_priv=private_key,
        static_pub=other_public_key,
        kdf=kdf
    )


# ==================================================
# 3. ECC KEY EXCHANGE
# ==================================================

def ecc_key_exchange():

    # Generate Alice's ECC key pair
    alice_private, alice_public = generate_ecc_keys()

    # Generate Bob's ECC key pair
    bob_private, bob_public = generate_ecc_keys()

    # Alice derives shared key using Bob's public key
    alice_shared = generate_shared_key(
        alice_private,
        bob_public
    )

    # Bob derives shared key using Alice's public key
    bob_shared = generate_shared_key(
        bob_private,
        alice_public
    )

    print("\nAlice Public Key:")
    print(alice_public.export_key(format="PEM"))

    print("\nBob Public Key:")
    print(bob_public.export_key(format="PEM"))

    print("Alice Shared Key:", alice_shared.hex())
    print("Bob Shared Key:", bob_shared.hex())

    print("Keys Match:", alice_shared == bob_shared)


# ==================================================
# 4. MAIN MENU
# ==================================================

def main():

    while True:
        print("\n===== ECC KEY EXCHANGE =====")
        print("1. Perform ECDH Key Exchange")
        print("2. Exit")

        choice = input("Choice: ")

        if choice == "1":
            ecc_key_exchange()

        elif choice == "2":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

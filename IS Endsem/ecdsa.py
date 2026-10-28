
from Cryptodome.PublicKey import ECC
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS


# ==================================================
# 1. GENERATE ECC KEY PAIR
# ==================================================

def generate_keys():

    # Generate ECC private key using P-256 curve
    private_key = ECC.generate(curve="P-256")

    # Extract public key for signature verification
    public_key = private_key.public_key()

    return private_key, public_key


# ==================================================
# 2. ECDSA SIGNATURE
# ==================================================

def ecdsa_sign(message, private_key):

    # Calculate SHA-256 hash of message
    digest = SHA256.new(message.encode())

    # Create ECDSA signer using deterministic signatures
    signer = DSS.new(
        private_key,
        "deterministic-rfc6979"
    )

    # Sign the message hash
    return signer.sign(digest)


# ==================================================
# 3. ECDSA VERIFICATION
# ==================================================

def ecdsa_verify(message, signature, public_key):

    # Calculate SHA-256 hash of received message
    digest = SHA256.new(message.encode())

    verifier = DSS.new(
        public_key,
        "deterministic-rfc6979"
    )

    try:
        verifier.verify(digest, signature)
        return True

    except ValueError:
        return False


# ==================================================
# 4. DIGITAL SIGNATURE DEMONSTRATION
# ==================================================

def signature_demo():

    private_key, public_key = generate_keys()

    message = input("Enter message: ")

    # Sign original message
    signature = ecdsa_sign(message, private_key)

    print("\nECDSA Signature:", signature.hex())

    # Verify original message
    valid = ecdsa_verify(
        message,
        signature,
        public_key
    )

    print("Original Signature Valid:", valid)

    # Modify the original message
    modified = input("Enter modified message: ")

    # Verify modified message using original signature
    valid = ecdsa_verify(
        modified,
        signature,
        public_key
    )

    print("Modified Signature Valid:", valid)


# ==================================================
# 5. MAIN MENU
# ==================================================

def main():

    while True:
        print("\n===== ECDSA DIGITAL SIGNATURE =====")
        print("1. Sign and Verify Message")
        print("2. Exit")

        choice = input("Choice: ")

        if choice == "1":
            signature_demo()

        elif choice == "2":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

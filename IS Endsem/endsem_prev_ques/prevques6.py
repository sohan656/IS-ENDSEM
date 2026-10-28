'''
Take two inputs: number of boxes, cost of each box.
Validate the input (input should lie between 1 to n-1 where n is the RSA parameter) then proceed.
Encrypt the two inputs and pass it to a function which calculates their multiplication mod N.
Perform this calculation on encrypted values only.
Encryption is via RSA with values mentioned in the exam.
If the products match after decryption print verified.
Menu driven code to be followed and a modular approach is expected. No hardcoded values
'''
from Cryptodome.Util.number import GCD


# ==================================================
# 1. RSA ENCRYPTION
# ==================================================

def rsa_encrypt(message, e, n):

    # RSA encryption: c = m^e mod n
    return pow(message, e, n)


# ==================================================
# 2. RSA DECRYPTION
# ==================================================

def rsa_decrypt(ciphertext, d, n):

    # RSA decryption: m = c^d mod n
    return pow(ciphertext, d, n)


# ==================================================
# 3. HOMOMORPHIC MULTIPLICATION
# ==================================================

def homomorphic_multiply(c1, c2, n):

    # Multiply encrypted values modulo n
    # No decryption is performed here
    return (c1 * c2) % n


# ==================================================
# 4. VALIDATE INPUT
# ==================================================

def validate_input(value, n):

    # Input must lie between 1 and n-1
    return 1 <= value <= n - 1


# ==================================================
# 5. ENTER RSA PARAMETERS
# ==================================================

def enter_rsa_parameters():

    try:
        n = int(input("Enter RSA modulus (n): "))
        e = int(input("Enter public exponent (e): "))
        d = int(input("Enter private exponent (d): "))

        if n <= 2 or e <= 1 or d <= 1:
            print("Invalid RSA parameters")
            return None

        return n, e, d

    except ValueError:
        print("Enter valid integers")
        return None


# ==================================================
# 6. BOX COST CALCULATION
# ==================================================

def calculate_cost(n, e, d):

    try:
        boxes = int(input("Enter number of boxes: "))
        cost = int(input("Enter cost of each box: "))

    except ValueError:
        print("Invalid input. Enter integers only.")
        return

    # Validate both inputs
    if not validate_input(boxes, n):
        print(f"Number of boxes must be between 1 and {n-1}")
        return

    if not validate_input(cost, n):
        print(f"Cost must be between 1 and {n-1}")
        return

    # Encrypt number of boxes
    encrypted_boxes = rsa_encrypt(boxes, e, n)

    # Encrypt cost per box
    encrypted_cost = rsa_encrypt(cost, e, n)

    print("\nEncrypted number of boxes:", encrypted_boxes)
    print("Encrypted cost per box:", encrypted_cost)

    # Perform multiplication on ciphertexts only
    encrypted_product = homomorphic_multiply(
        encrypted_boxes,
        encrypted_cost,
        n
    )

    print("Encrypted product:", encrypted_product)

    # Decrypt only the final encrypted product
    decrypted_product = rsa_decrypt(
        encrypted_product,
        d,
        n
    )

    # Calculate expected product modulo n
    expected_product = (boxes * cost) % n

    print("\nExpected product mod n:", expected_product)
    print("Decrypted product:", decrypted_product)

    # Verify homomorphic property
    if decrypted_product == expected_product:
        print("VERIFIED")
    else:
        print("NOT VERIFIED")


# ==================================================
# 7. MAIN MENU
# ==================================================

def main():

    rsa_params = None

    while True:

        print("\n========== RSA HOMOMORPHIC SYSTEM ==========")
        print("1. Enter RSA Parameters")
        print("2. Calculate Encrypted Box Cost")
        print("3. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            rsa_params = enter_rsa_parameters()

        elif choice == "2":

            if rsa_params is None:
                print("Enter RSA parameters first")
                continue

            n, e, d = rsa_params

            calculate_cost(n, e, d)

        elif choice == "3":
            print("Exiting...")
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

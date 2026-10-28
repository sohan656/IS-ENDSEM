import hashlib

# ============================================================
# ELGAMAL ENCRYPTION
# ============================================================

print("========== ELGAMAL ENCRYPTION ==========")

# Public parameters
p = 23
g = 5

# Receiver's private key
x = 6

# Receiver's public key
y = pow(g, x, p)

print("p =", p)
print("g =", g)
print("Private key (x) =", x)
print("Public key (y) =", y)

# Message
m = 10

# Random value chosen by sender
k = 3

# Encryption
c1 = pow(g, k, p)

c2 = (m * pow(y, k, p)) % p

print("\nOriginal message =", m)
print("Random k =", k)
print("Ciphertext (c1, c2) =", (c1, c2))

# Decryption
s = pow(c1, x, p)

# Modular inverse of s
s_inverse = pow(s, -1, p)

decrypted_message = (c2 * s_inverse) % p

print("Shared value =", s)
print("Inverse of shared value =", s_inverse)
print("Decrypted message =", decrypted_message)

# Verification
if m == decrypted_message:
    print("ElGamal Verification: SUCCESS")
else:
    print("ElGamal Verification: FAILED")


# ============================================================
# SCHNORR DIGITAL SIGNATURE
# ============================================================

print("\n========== SCHNORR DIGITAL SIGNATURE ==========")

# Small demonstration parameters
p = 23
q = 11
alpha = 2

# Private key
private_key = 3

# Public key
public_key = pow(alpha, -private_key, p)

print("p =", p)
print("q =", q)
print("alpha =", alpha)
print("Private key =", private_key)
print("Public key =", public_key)

# Message
message = "HELLO"

# Random value
r = 4

# Calculate x
x_value = pow(alpha, r, p)

# Hash function
hash_input = message + str(x_value)

hash_value = int(
    hashlib.sha256(hash_input.encode()).hexdigest(),
    16
)

# e modulo q
e = hash_value % q

# Calculate y
y = (r + private_key * e) % q

print("\nMessage =", message)
print("Random r =", r)
print("x =", x_value)
print("e =", e)
print("y =", y)

print("\nSignature =", (e, y))

# ============================================================
# SCHNORR VERIFICATION
# ============================================================

# Calculate x'
x_verification = (
    pow(alpha, y, p) *
    pow(public_key, e, p)
) % p

# Calculate e'
verification_input = message + str(x_verification)

verification_hash = int(
    hashlib.sha256(verification_input.encode()).hexdigest(),
    16
)

e_prime = verification_hash % q

print("\nVerification x' =", x_verification)
print("Original e =", e)
print("Calculated e' =", e_prime)

if e == e_prime:
    print("Schnorr Verification: SUCCESS")
else:
    print("Schnorr Verification: FAILED")
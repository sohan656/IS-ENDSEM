
from Cryptodome.PublicKey import RSA

# Generate RSA Keys
key = RSA.generate(2048)

e = key.e
d = key.d
n = key.n

# Encryption
def encrypt(m):
    return pow(m, e, n)

# Decryption
def decrypt(c):
    return pow(c, d, n)

# Original Messages
m1 = 7
m2 = 3

# Encrypt Messages
c1 = encrypt(m1)
c2 = encrypt(m2)

print("Encrypted 7:", c1)
print("Encrypted 3:", c2)

# Homomorphic Multiplication
c_product = (c1 * c2) % n

print("Encrypted Product:", c_product)

# Decrypt Result
result = decrypt(c_product)

print("Decrypted Product:", result)
print("Original Product:", m1 * m2)
print("Verification:", result == m1 * m2)

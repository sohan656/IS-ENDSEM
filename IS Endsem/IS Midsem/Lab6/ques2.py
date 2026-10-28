print("========== DIFFIE-HELLMAN KEY EXCHANGE ==========")

# Publicly known values
p = 23
g = 5

print("Public prime p =", p)
print("Public generator g =", g)

# ============================================================
# ALICE
# ============================================================

alice_private = 6

alice_public = pow(g, alice_private, p)

print("\n--- Alice ---")
print("Alice private key =", alice_private)
print("Alice public key =", alice_public)

# ============================================================
# BOB
# ============================================================

bob_private = 15

bob_public = pow(g, bob_private, p)

print("\n--- Bob ---")
print("Bob private key =", bob_private)
print("Bob public key =", bob_public)

# ============================================================
# SHARED SECRET
# ============================================================

# Alice uses Bob's public key
alice_shared_key = pow(
    bob_public,
    alice_private,
    p
)

# Bob uses Alice's public key
bob_shared_key = pow(
    alice_public,
    bob_private,
    p
)

print("\n--- Shared Secret ---")
print("Alice calculated shared key =", alice_shared_key)
print("Bob calculated shared key   =", bob_shared_key)

# ============================================================
# VERIFICATION
# ============================================================

if alice_shared_key == bob_shared_key:
    print("\nDiffie-Hellman Verification: SUCCESS")
    print("Both parties have the same shared secret.")
else:
    print("\nDiffie-Hellman Verification: FAILED")
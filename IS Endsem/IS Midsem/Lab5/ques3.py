import hashlib
import random
import string
import time


# ---------------------------------------------------------
# 1. Generate random strings
# ---------------------------------------------------------

NUM_STRINGS = 100
STRING_LENGTH = 20


def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))


dataset = [
    generate_random_string(STRING_LENGTH)
    for _ in range(NUM_STRINGS)
]

dataset[0] = "hhelnnjdjndjn92ikjlj"
dataset[1] = "hhelnnjdjndjn92ikjlj"


# ---------------------------------------------------------
# 2. Hash computation functions
# ---------------------------------------------------------

def compute_md5(data):
    return hashlib.md5(data.encode()).hexdigest()


def compute_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()


def compute_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()


# ---------------------------------------------------------
# 3. Collision detection
# ---------------------------------------------------------

def detect_collisions(hash_values, dataset):
    hash_map = {}
    collisions = []

    for data, hash_value in zip(dataset, hash_values):

        if hash_value in hash_map:
            collisions.append(
                (hash_value, hash_map[hash_value], data)
            )
        else:
            hash_map[hash_value] = data

    return collisions


# ---------------------------------------------------------
# 4. Compute MD5 and measure time
# ---------------------------------------------------------

start_time = time.perf_counter()

md5_hashes = [
    compute_md5(data)
    for data in dataset
]

md5_time = time.perf_counter() - start_time


# ---------------------------------------------------------
# 5. Compute SHA-1 and measure time
# ---------------------------------------------------------

start_time = time.perf_counter()

sha1_hashes = [
    compute_sha1(data)
    for data in dataset
]

sha1_time = time.perf_counter() - start_time


# ---------------------------------------------------------
# 6. Compute SHA-256 and measure time
# ---------------------------------------------------------

start_time = time.perf_counter()

sha256_hashes = [
    compute_sha256(data)
    for data in dataset
]

sha256_time = time.perf_counter() - start_time


# ---------------------------------------------------------
# 7. Detect collisions
# ---------------------------------------------------------

md5_collisions = detect_collisions(md5_hashes, dataset)
sha1_collisions = detect_collisions(sha1_hashes, dataset)
sha256_collisions = detect_collisions(sha256_hashes, dataset)


# ---------------------------------------------------------
# 8. Display results
# ---------------------------------------------------------

print("=" * 60)
print("HASH FUNCTION PERFORMANCE EXPERIMENT")
print("=" * 60)

print(f"\nNumber of strings: {NUM_STRINGS}")
print(f"Length of each string: {STRING_LENGTH}")

print("\n--- Computation Time ---")

print(f"MD5     : {md5_time:.10f} seconds")
print(f"SHA-1   : {sha1_time:.10f} seconds")
print(f"SHA-256 : {sha256_time:.10f} seconds")


print("\n--- Collision Detection ---")

print(f"MD5 collisions     : {len(md5_collisions)}")
print(f"SHA-1 collisions   : {len(sha1_collisions)}")
print(f"SHA-256 collisions : {len(sha256_collisions)}")


# ---------------------------------------------------------
# 9. Display hashes
# ---------------------------------------------------------

print("\n--- Hash Values ---")

for i in range(NUM_STRINGS):
    print(f"\nString {i + 1}: {dataset[i]}")
    print(f"MD5     : {md5_hashes[i]}")
    print(f"SHA-1   : {sha1_hashes[i]}")
    print(f"SHA-256 : {sha256_hashes[i]}")


# ---------------------------------------------------------
# 10. Display collision details if any
# ---------------------------------------------------------

if md5_collisions:
    print("\nMD5 collisions:")
    for collision in md5_collisions:
        print(collision)

if sha1_collisions:
    print("\nSHA-1 collisions:")
    for collision in sha1_collisions:
        print(collision)

if sha256_collisions:
    print("\nSHA-256 collisions:")
    for collision in sha256_collisions:
        print(collision)
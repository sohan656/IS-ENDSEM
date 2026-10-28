from Cryptodome.Hash import (
    SHA1, SHA224, SHA256, SHA384, SHA512,
    SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHA512_224, SHA512_256,
    SHAKE128, SHAKE256
)

# SHA-1 
def sha1_hash(message):
    return SHA1.new(message.encode()).hexdigest()


# SHA-224
def sha224_hash(message):
    return SHA224.new(message.encode()).hexdigest()


# SHA-256
def sha256_hash(message):
    return SHA256.new(message.encode()).hexdigest()


# SHA-384
def sha384_hash(message):
    return SHA384.new(message.encode()).hexdigest()


# SHA-512
def sha512_hash(message):
    return SHA512.new(message.encode()).hexdigest()


# SHA-512/224
def sha512_224_hash(message):
    return SHA512_224.new(message.encode()).hexdigest()


# SHA-512/256
def sha512_256_hash(message):
    return SHA512_256.new(message.encode()).hexdigest()


# SHA3-224
def sha3_224_hash(message):
    return SHA3_224.new(message.encode()).hexdigest()


# SHA3-256
def sha3_256_hash(message):
    return SHA3_256.new(message.encode()).hexdigest()


# SHA3-384
def sha3_384_hash(message):
    return SHA3_384.new(message.encode()).hexdigest()


# SHA3-512
def sha3_512_hash(message):
    return SHA3_512.new(message.encode()).hexdigest()


# SHAKE128
def shake128_hash(message, length=32):
    return SHAKE128.new(message.encode()).read(length).hex()


# SHAKE256
def shake256_hash(message, length=64):
    return SHAKE256.new(message.encode()).read(length).hex()

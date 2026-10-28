from Cryptodome.Cipher import AES, DES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

# AES ECB

def aes_ecb_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), AES.block_size))

def aes_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


# AES CBC

def aes_cbc_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv, ciphertext

def aes_cbc_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


# AES CFB

def aes_cfb_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CFB)
    return cipher.iv, cipher.encrypt(message.encode())

def aes_cfb_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext).decode()


# AES OFB

def aes_ofb_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_OFB)
    return cipher.iv, cipher.encrypt(message.encode())

def aes_ofb_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    return cipher.decrypt(ciphertext).decode()


# AES CTR

def aes_ctr_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CTR)
    return cipher.nonce, cipher.encrypt(message.encode())

def aes_ctr_decrypt(nonce, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

# AES GCM

def aes_gcm_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, ciphertext, tag


def aes_gcm_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()
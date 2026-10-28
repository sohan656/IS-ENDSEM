from Cryptodome.Cipher import AES, DES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

# DES ECB

def des_ecb_encrypt(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), DES.block_size))

def des_ecb_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()


# DES CBC

def des_cbc_encrypt(message, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), DES.block_size))
    return cipher.iv, ciphertext

def des_cbc_decrypt(iv, ciphertext, key):
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()


# DES CFB

def des_cfb_encrypt(message, key):
    cipher = DES.new(key, DES.MODE_CFB)
    return cipher.iv, cipher.encrypt(message.encode())

def des_cfb_decrypt(iv, ciphertext, key):
    cipher = DES.new(key, DES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext).decode()


# DES OFB

def des_ofb_encrypt(message, key):
    cipher = DES.new(key, DES.MODE_OFB)
    return cipher.iv, cipher.encrypt(message.encode())

def des_ofb_decrypt(iv, ciphertext, key):
    cipher = DES.new(key, DES.MODE_OFB, iv=iv)
    return cipher.decrypt(ciphertext).decode()


# DES CTR

def des_ctr_encrypt(message, key):
    cipher = DES.new(key, DES.MODE_CTR)
    return cipher.nonce, cipher.encrypt(message.encode())

def des_ctr_decrypt(nonce, ciphertext, key):
    cipher = DES.new(key, DES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

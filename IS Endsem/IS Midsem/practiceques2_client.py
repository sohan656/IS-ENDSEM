import socket
import hashlib
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())


filename = input("Enter filename: ")

with open(filename, "rb") as f:
    data = f.read()


# Hash original file
file_hash = hashlib.sha256(data).hexdigest()


# Encrypt
cipher = PKCS1_OAEP.new(public_key)
encrypted_data = cipher.encrypt(data)


# Connect
client = socket.socket()
client.connect(("localhost", 5001))


# Send encrypted data size
client.sendall(len(encrypted_data).to_bytes(4, "big"))

# Send encrypted data
client.sendall(encrypted_data)

# Send hash
client.sendall(file_hash.encode())


print("File sent successfully.")

client.close()
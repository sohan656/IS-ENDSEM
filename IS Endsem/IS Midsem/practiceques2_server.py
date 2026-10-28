import socket
import hashlib
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

with open("public.pem", "wb") as f:
    f.write(public_key.export_key())


def receive_all(conn, size):
    data = b""
    while len(data) < size:
        data += conn.recv(size - len(data))
    return data


server = socket.socket()
server.bind(("localhost", 5001))
server.listen(1)

print("Server waiting...")

conn, addr = server.accept()
print("Client connected.")


# Receive encrypted file size
size = int.from_bytes(receive_all(conn, 4), "big")

# Receive encrypted file
encrypted_data = receive_all(conn, size)

# Receive hash
received_hash = receive_all(conn, 64).decode()


# Decrypt
cipher = PKCS1_OAEP.new(private_key)
decrypted_data = cipher.decrypt(encrypted_data)


# Hash decrypted file
calculated_hash = hashlib.sha256(decrypted_data).hexdigest()


# Check integrity
if calculated_hash == received_hash:
    print("Integrity: VALID")
else:
    print("Integrity: INVALID")


with open("received_file.txt", "wb") as f:
    f.write(decrypted_data)

conn.close()
server.close()
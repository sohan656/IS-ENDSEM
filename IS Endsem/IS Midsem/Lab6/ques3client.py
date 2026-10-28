import socket

# ============================================================
# DIFFIE-HELLMAN PARAMETERS
# ============================================================

p = 23
g = 5

# Client's private key
client_private = 6

# Client's public key
client_public = pow(g, client_private, p)

# ============================================================
# CONNECT TO SERVER
# ============================================================

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect(("localhost", 5001))

print("Connected to server.")

# ============================================================
# SEND CLIENT PUBLIC KEY
# ============================================================

client.send(
    str(client_public).encode()
)

print("Sent client public key:", client_public)

# ============================================================
# RECEIVE SERVER PUBLIC KEY
# ============================================================

server_public = int(
    client.recv(1024).decode()
)

print("Received server public key:", server_public)

# ============================================================
# CALCULATE SHARED SECRET
# ============================================================

shared_secret = pow(
    server_public,
    client_private,
    p
)

print("Client shared secret:", shared_secret)

# ============================================================
# SEND MESSAGE
# ============================================================

message = "Hello Server"

client.send(message.encode())

print("Message sent:", message)

# ============================================================
# CLOSE
# ============================================================

client.close()
import socket

# ============================================================
# DIFFIE-HELLMAN PARAMETERS
# ============================================================

p = 23
g = 5

# Server's private key
server_private = 15

# Server's public key
server_public = pow(g, server_private, p)

# ============================================================
# CREATE SERVER
# ============================================================

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(("localhost", 5001))
server.listen(1)

print("Server waiting for connection...")

conn, address = server.accept()

print("Client connected:", address)

# ============================================================
# RECEIVE CLIENT PUBLIC KEY
# ============================================================

client_public = int(
    conn.recv(1024).decode()
)

print("Received client public key:", client_public)

# ============================================================
# SEND SERVER PUBLIC KEY
# ============================================================

conn.send(
    str(server_public).encode()
)

print("Sent server public key:", server_public)

# ============================================================
# CALCULATE SHARED SECRET
# ============================================================

shared_secret = pow(
    client_public,
    server_private,
    p
)

print("Server shared secret:", shared_secret)

# ============================================================
# RECEIVE MESSAGE
# ============================================================

message = conn.recv(1024).decode()

print("Received message:", message)

# ============================================================
# CLOSE CONNECTION
# ============================================================

conn.close()
server.close()
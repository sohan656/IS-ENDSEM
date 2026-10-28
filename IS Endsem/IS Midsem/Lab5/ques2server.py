import socket


def hash_function(input_string):
    hash_value = 5381

    for ch in input_string:
        hash_value = (hash_value * 33) + ord(ch)

        # Bitwise mixing
        hash_value ^= (hash_value >> 16)

        # Keep within 32 bits
        hash_value &= 0xFFFFFFFF

    return hash_value


# Create socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind to localhost and port 12345
server_socket.bind(("127.0.0.1", 12345))

# Listen for connection
server_socket.listen(1)

print("Server waiting for connection...")

# Accept client connection
client_socket, address = server_socket.accept()

print("Client connected:", address)

# Receive data
data = client_socket.recv(1024).decode()

print("Received data:", data)

# Calculate hash of received data
received_hash = hash_function(data)

print("Calculated hash:", received_hash)

# Send hash back to client
client_socket.send(str(received_hash).encode())

# Close sockets
client_socket.close()
server_socket.close()
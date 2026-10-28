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


# Original data
data = "Sensitive Information"

# Calculate hash before transmission
original_hash = hash_function(data)

print("Original data:", data)
print("Original hash:", original_hash)


# -------------------------------------------------
# Uncomment the following two lines to simulate
# data corruption/tampering
# -------------------------------------------------

# data = "Sensitive InformatioX"


# Create socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to server
client_socket.connect(("127.0.0.1", 12345))

# Send data
client_socket.send(data.encode())

# Receive hash from server
server_hash = int(client_socket.recv(1024).decode())

print("Hash received from server:", server_hash)

# Calculate hash of the data that was sent
local_hash = hash_function(data)

print("Locally calculated hash:", local_hash)

# Compare hashes
if local_hash == server_hash:
    print("Integrity verified: Data was not corrupted.")
else:
    print("Integrity check failed: Data may have been corrupted or tampered with.")

client_socket.close()
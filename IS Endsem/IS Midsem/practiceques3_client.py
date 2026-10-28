import socket
import hashlib
import json

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


# ---------------- GET PUBLIC KEY ----------------

with open("public.pem", "rb") as f:

    public_key = RSA.import_key(
        f.read()
    )


# ---------------- LOGIN ----------------

username = input("Username: ")

password = input("Password: ")


# ---------------- CONNECT ----------------

client = socket.socket()

client.connect(
    ("localhost", 5001)
)


# ---------------- SEND LOGIN ----------------

login = username + "|" + password
client.sendall(login.encode())


response = client.recv(1024).decode()

print(response)


if response == "Login failed":

    client.close()
    exit()


# ---------------- MENU ----------------

print("\n1. View Record")
print("2. Update CGPA")
print("3. Add Record")


choice = input("Enter choice: ")


# ---------------- VIEW ----------------

if choice == "1":

    student_id = input(
        "Enter student ID: "
    )

    request = {
        "operation": "view",
        "student_id": student_id
    }


# ---------------- UPDATE ----------------

elif choice == "2":

    student_id = input(
        "Enter student ID: "
    )

    cgpa = float(
        input("Enter new CGPA: ")
    )

    request = {
        "operation": "update",
        "student_id": student_id,
        "cgpa": cgpa
    }


# ---------------- ADD ----------------

elif choice == "3":

    student_id = input(
        "Enter student ID: "
    )

    name = input(
        "Enter name: "
    )

    department = input(
        "Enter department: "
    )

    cgpa = float(
        input("Enter CGPA: ")
    )

    semester = int(
        input("Enter semester: ")
    )

    request = {
        "operation": "add",
        "student_id": student_id,
        "name": name,
        "department": department,
        "cgpa": cgpa,
        "semester": semester
    }


else:

    print("Invalid choice")

    client.close()
    exit()


# ---------------- CONVERT TO BYTES ----------------

data = json.dumps(request).encode()


# ---------------- HASH ----------------

file_hash = hashlib.sha256(
    data
).hexdigest()


# ---------------- ENCRYPT ----------------

cipher = PKCS1_OAEP.new(
    public_key
)

encrypted_data = cipher.encrypt(
    data
)


# ---------------- SEND SIZE ----------------

client.sendall(
    len(encrypted_data).to_bytes(
        4,
        "big"
    )
)


# ---------------- SEND ENCRYPTED DATA ----------------

client.sendall(
    encrypted_data
)


# ---------------- SEND HASH ----------------

client.sendall(
    file_hash.encode()
)


# ---------------- RECEIVE RESULT ----------------

size = int.from_bytes(
    client.recv(4),
    "big"
)

result = client.recv(size)


print("\nServer response:")

print(
    json.loads(
        result.decode()
    )
)


client.close()
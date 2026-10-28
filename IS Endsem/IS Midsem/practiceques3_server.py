import socket
import hashlib
import json

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


# ---------------- RSA KEYS ----------------

key = RSA.generate(2048)

private_key = key
public_key = key.publickey()

with open("public.pem", "wb") as f:
    f.write(public_key.export_key())


# ---------------- USERS ----------------

users = {
    "student1": ["1234", "student", "S101"],
    "faculty1": ["1234", "faculty", ""],
    "hod1": ["1234", "hod", ""]
}


# ---------------- STUDENT RECORDS ----------------

records = {
    "S101": {
        "name": "Rahul",
        "department": "CSE",
        "cgpa": 8.5,
        "semester": 5
    },

    "S102": {
        "name": "Priya",
        "department": "CSE",
        "cgpa": 9.1,
        "semester": 5
    }
}


# ---------------- SOCKET ----------------

server = socket.socket()

server.bind(("localhost", 5001))

server.listen(1)

print("Server waiting...")

conn, addr = server.accept()

print("Client connected.")


# ---------------- LOGIN ----------------

login = conn.recv(1024).decode()

username, password = login.split("|")

if username not in users or users[username][0] != password:

    conn.sendall(b"Login failed")
    conn.close()
    server.close()
    exit()

role = users[username][1]

student_id = users[username][2]

print("Login successful")
print("Role:", role)

conn.sendall(b"Login successful")


# ---------------- RECEIVE DATA ----------------

size = int.from_bytes(
    conn.recv(4),
    "big"
)

encrypted_data = conn.recv(size)

received_hash = conn.recv(64).decode()


# ---------------- DECRYPT ----------------

cipher = PKCS1_OAEP.new(private_key)

decrypted_data = cipher.decrypt(encrypted_data)


# ---------------- HASH ----------------

calculated_hash = hashlib.sha256(
    decrypted_data
).hexdigest()


if calculated_hash == received_hash:

    print("Integrity: VALID")

else:

    print("Integrity: INVALID")

    conn.close()
    server.close()
    exit()


# Convert JSON to dictionary

request = json.loads(
    decrypted_data.decode()
)


# ---------------- OPERATIONS ----------------

operation = request["operation"]


# VIEW

if operation == "view":

    requested_id = request["student_id"]

    # Student can only view own record

    if role == "student":

        if requested_id != student_id:

            result = "Access denied"

        else:

            result = records[requested_id]


    else:

        # Faculty and HOD can view any record

        result = records[requested_id]


# UPDATE

elif operation == "update":

    if role == "student":

        result = "Access denied"

    else:

        requested_id = request["student_id"]

        new_cgpa = request["cgpa"]

        records[requested_id]["cgpa"] = new_cgpa

        result = "Record updated"


# ADD

elif operation == "add":

    if role != "hod":

        result = "Access denied"

    else:

        requested_id = request["student_id"]

        records[requested_id] = {
            "name": request["name"],
            "department": request["department"],
            "cgpa": request["cgpa"],
            "semester": request["semester"]
        }

        result = "Record added"


else:

    result = "Invalid operation"


# ---------------- SEND RESULT ----------------

result = json.dumps(result).encode()

conn.sendall(
    len(result).to_bytes(4, "big")
)

conn.sendall(result)


conn.close()
server.close()
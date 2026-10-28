'''
Question 4: Secure Healthcare Access Using Multiple Authorization Policies
20 marks
New concepts: DAC, MAC, ABAC, role-based access and temporary permissions

A hospital stores encrypted patient records. Doctors, nurses, receptionists and administrators have different access permissions.

The hospital wants to combine multiple access control models to protect patient information.
Requirements
1. AES Encryption (3 marks): Encrypt patient records using AES-GCM.
2. RBAC (3 marks): Implement different permissions for Doctor, Nurse, Receptionist and Admin.
3. Discretionary Access Control (3 marks): Allow the record owner to grant or revoke read access for specific users.
4. Mandatory Access Control (3 marks): Assign classification levels to patient records and clearance levels to employees.
5. Temporary Permissions (3 marks): Grant access for 60 seconds, after which access is automatically denied.
6. Audit Logging and Integration (5 marks): Record successful and denied access attempts, permission changes and expired access.
'''


import time

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


aes_key = get_random_bytes(32)

# Role permissions
ROLE_PERMISSIONS = {
    "Doctor": {"read", "write"},
    "Nurse": {"read"},
    "Receptionist": {"read"},
    "Admin": {"read", "write", "grant", "revoke"}
}

# Clearance levels for MAC
CLEARANCE = {
    "Receptionist": 1,
    "Nurse": 2,
    "Doctor": 3,
    "Admin": 4
}

users = {
    "U101": {"role": "Doctor"},
    "U102": {"role": "Nurse"},
    "U103": {"role": "Receptionist"},
    "U104": {"role": "Admin"}
}

records = {}
permissions = {}
audit_log = []


def audit(action, details):
    entry = (
        time.strftime("%Y-%m-%d %H:%M:%S"),
        action,
        details
    )

    audit_log.append(entry)
    print("[AUDIT]", *entry)


# Encrypt patient data using AES-GCM
def encrypt_data(message):
    cipher = AES.new(aes_key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(
        message.encode()
    )

    return cipher.nonce, ciphertext, tag


# Decrypt and authenticate the stored record
def decrypt_data(package):
    nonce, ciphertext, tag = package

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    return cipher.decrypt_and_verify(
        ciphertext, tag
    ).decode()


# Create a patient record with owner and classification
def add_record():
    record_id = input("Record ID: ").strip()
    owner = input("Owner user ID: ").strip()

    if record_id in records or owner not in users:
        print("Invalid record or owner")
        return

    classification = int(input("Classification (1-4): "))

    if classification not in range(1, 5):
        print("Invalid classification")
        return

    content = input("Patient information: ")

    records[record_id] = {
        "owner": owner,
        "classification": classification,
        "package": encrypt_data(content)
    }

    audit("RECORD_CREATED", record_id)


# Grant temporary access to another user
def grant_access():
    owner = input("Owner ID: ").strip()
    user_id = input("User to grant access: ").strip()
    record_id = input("Record ID: ").strip()

    if record_id not in records or user_id not in users:
        print("Invalid record or user")
        return

    if records[record_id]["owner"] != owner:
        print("Only the owner can grant access")
        return

    # Store expiry 60 seconds from now
    permissions[(user_id, record_id)] = time.time() + 60

    audit("ACCESS_GRANTED", f"{user_id}: {record_id}")


# Remove a previously granted permission
def revoke_access():
    owner = input("Owner ID: ").strip()
    user_id = input("User ID: ").strip()
    record_id = input("Record ID: ").strip()

    if record_id not in records:
        print("Record not found")
        return

    if records[record_id]["owner"] != owner:
        print("Only owner can revoke access")
        return

    # pop(..., None) avoids an error if permission is absent
    permissions.pop((user_id, record_id), None)

    audit("ACCESS_REVOKED", f"{user_id}: {record_id}")


# Combine RBAC, MAC and temporary DAC permission
def check_access(user_id, record_id, operation):
    user = users.get(user_id)
    record = records.get(record_id)

    if user is None or record is None:
        return False

    role = user["role"]

    # RBAC: role must permit the requested operation
    if operation not in ROLE_PERMISSIONS[role]:
        return False

    # MAC: clearance must be sufficient
    if CLEARANCE[role] < record["classification"]:
        return False

    # Owner or Admin can access without a temporary DAC grant
    if user_id == record["owner"] or role == "Admin":
        return True

    expiry = permissions.get((user_id, record_id), 0)

    # DAC permission must still be within its validity period
    return time.time() < expiry


# View one patient record
def view_record():
    user_id = input("User ID: ").strip()
    record_id = input("Record ID: ").strip()

    if not check_access(user_id, record_id, "read"):
        audit("ACCESS_DENIED", f"{user_id}: {record_id}")
        return

    try:
        plaintext = decrypt_data(records[record_id]["package"])
        print("Patient record:", plaintext)

        audit("RECORD_VIEWED", f"{user_id}: {record_id}")

    except ValueError:
        audit("AUTHENTICATION_FAILED", record_id)


# Modify an existing record
def update_record():
    user_id = input("User ID: ").strip()
    record_id = input("Record ID: ").strip()

    if not check_access(user_id, record_id, "write"):
        audit("WRITE_DENIED", f"{user_id}: {record_id}")
        return

    new_content = input("New content: ")

    records[record_id]["package"] = encrypt_data(new_content)

    audit("RECORD_UPDATED", f"{user_id}: {record_id}")


def show_audit():
    for entry in audit_log:
        print(entry)


def main():
    while True:
        print("\n--- HEALTHCARE SECURITY ---")
        print("1. Add Patient Record")
        print("2. Grant Temporary Access")
        print("3. Revoke Access")
        print("4. View Patient Record")
        print("5. Update Patient Record")
        print("6. Audit Log")
        print("7. Exit")

        choice = input("Choice: ")

        try:
            if choice == "1":
                add_record()

            elif choice == "2":
                grant_access()

            elif choice == "3":
                revoke_access()

            elif choice == "4":
                view_record()

            elif choice == "5":
                update_record()

            elif choice == "6":
                show_audit()

            elif choice == "7":
                break

            else:
                print("Invalid choice")

        except (ValueError, KeyError) as e:
            print("Error:", e)


if __name__ == "__main__":
    main()
 
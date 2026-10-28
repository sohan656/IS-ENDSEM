'''
Question 3: Secure Employee Payroll with Cryptographic Auditing
20 marks
New concepts: HMAC authentication, tamper-evident audit logs, key separation and replay prevention

A company stores employee salary records and allows authorized payroll officers to process payments.

The company wants to detect unauthorized changes to salary records and maintain a tamper-evident history of all operations.
Requirements
1. AES-192 CBC (3 marks): Encrypt employee IDs, departments and salary information.
2. KDF (3 marks): Derive a 24-byte AES key using PBKDF2 with 25 iterations.
3. HMAC-SHA256 (4 marks): Generate an authentication tag for every encrypted record. Reject records whose tags do not match.
4. Tamper-Evident Audit Log (4 marks): Link consecutive audit entries using SHA-256 so that modifying an earlier entry causes verification to fail.
5. Replay Prevention (3 marks): Assign a unique transaction ID to each payroll request and reject repeated IDs.
6. Integration (3 marks): Implement Admin and Payroll Staff menus.
'''


import time
import json
import hmac
import hashlib

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


PASSWORD = b"PayrollLabPassword"

# Separate key for HMAC authentication
hmac_key = get_random_bytes(32)

employees = {}
processed_transactions = set()
audit_log = []

# Authentication is simplified to lab roles
ROLE_PERMISSIONS = {
    "Staff": {"add", "pay"},
    "Admin": {"add", "pay", "view", "audit", "tamper"}
}


# Create a SHA-256-linked audit entry
def audit(action, details=""):
    previous_hash = (
        audit_log[-1]["hash"]
        if audit_log
        else "0" * 64
    )

    entry = {
        "time": time.time(),
        "action": action,
        "details": details,
        "previous_hash": previous_hash
    }

    # sort_keys=True keeps JSON field order consistent
    data = json.dumps(entry, sort_keys=True).encode()

    entry["hash"] = hashlib.sha256(data).hexdigest()

    audit_log.append(entry)
    print("[AUDIT]", action, details)


# Recalculate every entry's hash and previous-hash link
def verify_audit_chain():
    previous_hash = "0" * 64

    for entry in audit_log:
        if entry["previous_hash"] != previous_hash:
            return False

        data = {
            key: value
            for key, value in entry.items()
            if key != "hash"
        }

        expected = hashlib.sha256(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest()

        if not hmac.compare_digest(expected, entry["hash"]):
            return False

        previous_hash = entry["hash"]

    return True


# Derive a 24-byte AES-192 key
def derive_key(salt):
    return PBKDF2(
        PASSWORD,
        salt,
        dkLen=24,              # AES-192 key
        count=25,              # 25 KDF iterations
        hmac_hash_module=SHA256
    )


def encrypt_text(message, key):
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(message.encode(), AES.block_size)
    )

    return cipher.iv, ciphertext


def decrypt_text(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    return unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    ).decode()


# Calculate HMAC over IV and ciphertext
def create_tag(iv, ciphertext):
    return hmac.new(
        hmac_key,
        iv + ciphertext,
        hashlib.sha256
    ).digest()


# Compare the saved tag with the newly calculated tag
def verify_tag(iv, ciphertext, tag):
    expected = create_tag(iv, ciphertext)

    return hmac.compare_digest(expected, tag)


# Add an encrypted employee record
def add_employee():
    emp_id = input("Employee ID: ").strip()

    if not emp_id or emp_id in employees:
        print("Invalid or duplicate employee ID")
        return

    department = input("Department: ")
    salary = int(input("Salary: "))

    if salary < 0:
        print("Salary cannot be negative")
        return

    message = f"{emp_id}|{department}|{salary}"

    salt = get_random_bytes(16)
    key = derive_key(salt)

    iv, ciphertext = encrypt_text(message, key)
    tag = create_tag(iv, ciphertext)

    employees[emp_id] = {
        "salt": salt,
        "iv": iv,
        "ciphertext": ciphertext,
        "tag": tag
    }

    audit("EMPLOYEE_ADDED", emp_id)


# Verify HMAC before decrypting a selected employee
def view_employee():
    emp_id = input("Employee ID: ").strip()

    if emp_id not in employees:
        print("Employee not found")
        return

    record = employees[emp_id]

    valid = verify_tag(
        record["iv"],
        record["ciphertext"],
        record["tag"]
    )

    print("HMAC valid:", valid)

    if not valid:
        audit("HMAC_FAILED", emp_id)
        return

    key = derive_key(record["salt"])

    plaintext = decrypt_text(
        record["iv"],
        record["ciphertext"],
        key
    )

    print("Record:", plaintext)
    audit("EMPLOYEE_VIEWED", emp_id)


# Reject a transaction ID already processed
def process_payment():
    transaction_id = input("Transaction ID: ").strip()
    emp_id = input("Employee ID: ").strip()

    if not transaction_id or transaction_id in processed_transactions:
        audit("REPLAY_REJECTED", transaction_id)
        return

    if emp_id not in employees:
        print("Employee not found")
        return

    record = employees[emp_id]

    if not verify_tag(
        record["iv"],
        record["ciphertext"],
        record["tag"]
    ):
        audit("PAYMENT_REJECTED", "HMAC verification failed")
        return

    # Add ID only after validation succeeds
    processed_transactions.add(transaction_id)

    audit("PAYMENT_PROCESSED", f"{transaction_id}: {emp_id}")
    print("Payment request accepted")


# Change ciphertext without updating its HMAC
def tamper_record():
    emp_id = input("Employee ID: ").strip()

    if emp_id not in employees:
        print("Employee not found")
        return

    record = employees[emp_id]
    modified = bytearray(record["ciphertext"])

    modified[0] ^= 1
    record["ciphertext"] = bytes(modified)

    audit("RECORD_TAMPERED", emp_id)


# Change an existing audit entry for verification testing
def tamper_audit():
    if not audit_log:
        print("Audit log is empty")
        return

    audit_log[0]["details"] = "MODIFIED"
    print("First audit entry modified")

    print("Audit chain valid:", verify_audit_chain())


def show_audit():
    for entry in audit_log:
        print(entry)

    print("Audit chain valid:", verify_audit_chain())


def main():
    while True:
        print("\n--- PAYROLL MANAGEMENT ---")
        print("1. Staff")
        print("2. Admin")
        print("3. Exit")

        role_choice = input("Choice: ")

        if role_choice == "3":
            break

        if role_choice not in ("1", "2"):
            print("Invalid role")
            continue

        role = "Staff" if role_choice == "1" else "Admin"

        while True:
            print(f"\n--- {role.upper()} MENU ---")
            print("1. Add Employee")
            print("2. Process Payment")
            print("3. View Employee")
            print("4. Tamper Record (Demo)")
            print("5. View Audit")
            print("6. Tamper Audit (Demo)")
            print("7. Back")

            choice = input("Choice: ")

            actions = {
                "1": "add",
                "2": "pay",
                "3": "view",
                "4": "tamper",
                "5": "audit",
                "6": "tamper"
            }

            if choice == "7":
                break

            action = actions.get(choice)

            if action not in ROLE_PERMISSIONS[role]:
                audit("ACCESS_DENIED", f"{role}: option {choice}")
                continue

            try:
                if choice == "1":
                    add_employee()
                elif choice == "2":
                    process_payment()
                elif choice == "3":
                    view_employee()
                elif choice == "4":
                    tamper_record()
                elif choice == "5":
                    show_audit()
                elif choice == "6":
                    tamper_audit()

            except (ValueError, KeyError) as e:
                print("Error:", e)


if __name__ == "__main__":
    main()

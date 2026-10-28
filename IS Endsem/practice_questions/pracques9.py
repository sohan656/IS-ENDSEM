'''
Question 6: Secure Research Database with Searchable Encryption and Access Expiry
20 marks
New concepts: Search-token expiry, multi-keyword queries, index revocation and search leakage

A research organization stores confidential research reports containing report ID, department, description, classification and publication date.

The organization wants to allow authorized users to search encrypted reports without revealing their contents.
Requirements
1. AES-256 Encryption (3 marks): Encrypt all research reports using AES-CBC.
2. HMAC Searchable Index (4 marks): Create HMAC-SHA256 tokens for description keywords.
3. Multi-Keyword Search (3 marks): Support AND and OR searches without decrypting all reports.
4. Time-Limited Search Access (3 marks): Issue search permissions valid for 120 seconds.
5. Index Revocation (3 marks): Remove a report from the searchable index when it is deleted or access is revoked.
6. Integration and Auditing (4 marks): Record searches, expired permissions and deleted index entries.
'''


import time
import re
import hmac
import hashlib

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


aes_key = get_random_bytes(32)
search_key = get_random_bytes(32)

reports = {}
search_index = {}
search_permissions = {}
audit_log = []


def audit(action, details=""):
    entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "details": details
    }

    audit_log.append(entry)
    print("[AUDIT]", entry)


# Encrypt report text using AES-256 CBC
def encrypt_text(message):
    cipher = AES.new(aes_key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(message.encode(), AES.block_size)
    )

    return cipher.iv, ciphertext


# Decrypt one selected report
def decrypt_text(iv, ciphertext):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)

    return unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    ).decode()


# Convert description into lowercase keywords
def extract_keywords(description):
    return set(
        re.findall(r"[a-z0-9]+", description.lower())
    )


# Generate an HMAC token for one keyword
def make_token(word):
    return hmac.new(
        search_key,
        word.lower().encode(),
        hashlib.sha256
    ).hexdigest()


# Add a report ID to each matching keyword index
def add_to_index(report_id, description):
    for word in extract_keywords(description):
        token = make_token(word)

        search_index.setdefault(
            token, set()
        ).add(report_id)


# Remove all index references to a report
def remove_from_index(report_id):
    for token in list(search_index.keys()):

        search_index[token].discard(report_id)

        if not search_index[token]:
            del search_index[token]


# Add and encrypt a research report
def add_report():
    report_id = input("Report ID: ").strip()

    if not report_id or report_id in reports:
        print("Invalid or duplicate ID")
        return

    department = input("Department: ").strip()
    description = input("Description: ").strip()
    classification = input("Classification: ").strip()
    publication_date = input("Publication date: ").strip()

    if not all([
        department,
        description,
        classification,
        publication_date
    ]):
        print("All fields are required")
        return

    message = (
        f"{report_id}|{department}|{description}|"
        f"{classification}|{publication_date}"
    )

    iv, ciphertext = encrypt_text(message)

    reports[report_id] = {
        "iv": iv,
        "ciphertext": ciphertext,
        "deleted": False
    }

    add_to_index(report_id, description)

    audit("REPORT_ADDED", report_id)


# Give a user permission to search for 120 seconds
def grant_search_permission():
    user_id = input("User ID: ").strip()

    if not user_id:
        print("Invalid user")
        return

    expiry = time.time() + 120

    search_permissions[user_id] = expiry

    print(
        "Search expires at:",
        time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(expiry)
        )
    )

    audit("SEARCH_PERMISSION_GRANTED", user_id)


# Check whether the search permission is still active
def can_search(user_id):
    expiry = search_permissions.get(user_id, 0)

    return time.time() < expiry


# Search multiple encrypted keywords
def multi_keyword_search(words, operation="AND"):
    result_sets = []

    for word in words:
        token = make_token(word)

        result_sets.append(
            search_index.get(token, set())
        )

    if not result_sets:
        return set()

    if operation == "AND":
        return set.intersection(*result_sets)

    elif operation == "OR":
        return set.union(*result_sets)

    return set()


# Search without decrypting the reports
def search_reports():
    user_id = input("User ID: ").strip()

    if not can_search(user_id):
        audit("SEARCH_DENIED", user_id)
        print("Permission expired or not granted")
        return

    query = input("Keywords (space separated): ").strip()

    operation = input("AND / OR: ").strip().upper()

    if operation not in ("AND", "OR"):
        print("Invalid search operation")
        return

    words = extract_keywords(query)

    matches = multi_keyword_search(
        words,
        operation
    )

    # Only return report IDs, not decrypted contents
    print("Matching report IDs:", sorted(matches))

    audit(
        "SEARCH_PERFORMED",
        f"{user_id}: {query} ({operation})"
    )


# Decrypt only a report explicitly selected by the user
def view_report():
    user_id = input("User ID: ").strip()

    if not can_search(user_id):
        audit("VIEW_DENIED", user_id)
        print("Permission expired")
        return

    report_id = input("Report ID: ").strip()

    if report_id not in reports:
        print("Report not found")
        return

    if reports[report_id]["deleted"]:
        print("Report deleted")
        return

    report = reports[report_id]

    plaintext = decrypt_text(
        report["iv"],
        report["ciphertext"]
    )

    print("Report:", plaintext)

    audit("REPORT_VIEWED", f"{user_id}: {report_id}")


# Revoke a report from the searchable index
def delete_report():
    report_id = input("Report ID: ").strip()

    if report_id not in reports:
        print("Report not found")
        return

    # Remove all searchable references
    remove_from_index(report_id)

    # Mark the record as deleted
    reports[report_id]["deleted"] = True

    audit("REPORT_DELETED", report_id)


# Revoke a user's search permission immediately
def revoke_search_permission():
    user_id = input("User ID: ").strip()

    search_permissions.pop(user_id, None)

    audit("SEARCH_PERMISSION_REVOKED", user_id)


def show_audit():
    for entry in audit_log:
        print(entry)


def main():
    while True:
        print("\n--- RESEARCH DATABASE ---")
        print("1. Add Report")
        print("2. Grant Search Permission")
        print("3. Search Reports")
        print("4. View Individual Report")
        print("5. Delete Report")
        print("6. Revoke Search Permission")
        print("7. View Audit Log")
        print("8. Exit")

        choice = input("Choice: ")

        try:
            if choice == "1":
                add_report()

            elif choice == "2":
                grant_search_permission()

            elif choice == "3":
                search_reports()

            elif choice == "4":
                view_report()

            elif choice == "5":
                delete_report()

            elif choice == "6":
                revoke_search_permission()

            elif choice == "7":
                show_audit()

            elif choice == "8":
                break

            else:
                print("Invalid choice")

        except (ValueError, KeyError) as e:
            print("Error:", e)


if __name__ == "__main__":
    main()

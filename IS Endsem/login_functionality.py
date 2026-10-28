
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import hmac


# Stores usernames, password hashes, salts and roles
users = {}

# Stores confidential content
records = {
    "R101": "Confidential financial report",
    "R102": "Employee salary information",
    "R103": "Internal audit document"
}

# Stores the currently logged-in username
current_user = None


# ==================================================
# 1. HASH PASSWORD
# ==================================================

def hash_password(password, salt):

    # Combine salt and password before hashing
    data = salt + password.encode()

    # Return SHA-256 hash as bytes
    return SHA256.new(data).digest()


# ==================================================
# 2. REGISTER USER
# ==================================================

def register():

    username = input("Create username: ").strip()
    password = input("Create password: ")

    if not username or not password:
        print("Username and password cannot be empty")
        return

    if username in users:
        print("Username already exists")
        return

    # Assign Staff role to newly registered users
    role = "Staff"

    # Generate a random 16-byte salt for this user
    salt = get_random_bytes(16)

    # Hash password using SHA-256 and the generated salt
    password_hash = hash_password(password, salt)

    # Store user details in dictionary
    users[username] = {
        "password_hash": password_hash,
        "salt": salt,
        "role": role
    }

    print("User registered successfully")


# ==================================================
# 3. LOGIN
# ==================================================

def login():

    global current_user

    username = input("Username: ").strip()
    password = input("Password: ")

    if username not in users:
        print("User not found")
        return

    user = users[username]

    # Hash entered password using stored salt
    entered_hash = hash_password(
        password,
        user["salt"]
    )

    # Compare entered hash with stored hash
    if hmac.compare_digest(
        entered_hash,
        user["password_hash"]
    ):
        current_user = username
        print("Login successful")
        print("Role:", user["role"])

    else:
        print("Incorrect password")


# ==================================================
# 4. LOGOUT
# ==================================================

def logout():

    global current_user

    current_user = None
    print("Logged out successfully")


# ==================================================
# 5. VIEW RECORD
# ==================================================

def view_record():

    # Deny access if nobody is logged in
    if current_user is None:
        print("Please login first")
        return

    record_id = input("Enter record ID: ").strip().upper()

    if record_id not in records:
        print("Record not found")
        return

    # Only Admin users can view confidential records
    if users[current_user]["role"] != "Admin":
        print("Access denied: Admin only")
        return

    print("Record:", records[record_id])


# ==================================================
# 6. ADD RECORD
# ==================================================

def add_record():

    if current_user is None:
        print("Please login first")
        return

    # Staff and Admin can add records
    if users[current_user]["role"] not in ("Staff", "Admin"):
        print("Access denied")
        return

    record_id = input("Record ID: ").strip().upper()
    content = input("Record content: ")

    if record_id in records:
        print("Record already exists")
        return

    records[record_id] = content

    print("Record added successfully")


# ==================================================
# 7. CREATE DEFAULT ADMIN
# ==================================================

def create_admin():

    # Create one predefined Admin account
    username = "admin"
    password = "admin123"

    salt = get_random_bytes(16)

    users[username] = {
        "password_hash": hash_password(password, salt),
        "salt": salt,
        "role": "Admin"
    }


# ==================================================
# 8. MAIN MENU
# ==================================================

def main():

    create_admin()

    while True:

        print("\n========== LOGIN SYSTEM ==========")
        print("1. Register")
        print("2. Login")
        print("3. Logout")
        print("4. Add Record")
        print("5. View Record")
        print("6. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            register()

        elif choice == "2":
            login()

        elif choice == "3":
            logout()

        elif choice == "4":
            add_record()

        elif choice == "5":
            view_record()

        elif choice == "6":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

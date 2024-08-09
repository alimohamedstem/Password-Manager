import hashlib
import os
import getpass

def create_master_key():
    master_key = getpass.getpass("Create your master key: ")
    hashed_master_key = hashlib.sha256(master_key.encode()).hexdigest()
    # Store hashed master key securely (in this case, just as a variable)
    with open("master_key.txt", "w") as f:
        f.write(hashed_master_key)
    print("Master key created and saved.")

def authenticate_master_key():
    with open("master_key.txt", "r") as f:
        hashed_master_key = f.read().strip()
    input_master_key = getpass.getpass("Enter your master key: ")
    hashed_input_master_key = hashlib.sha256(input_master_key.encode()).hexdigest()
    return hashed_master_key == hashed_input_master_key

def edit_master_key():
    with open("master_key.txt", "r") as f:
        hashed_master_key = f.read().strip()
    if authenticate_master_key():
        new_master_key = getpass.getpass("Enter new master key: ")
        hashed_new_master_key = hashlib.sha256(new_master_key.encode()).hexdigest()
        with open("master_key.txt", "w") as f:
            f.write(hashed_new_master_key)
        print("Master key updated successfully.")
    else:
        print("Authentication failed. Cannot edit master key.")

def store_password(domain, username, password):
    encryption_key = os.urandom(16) 
    encrypted_password = encrypt_password(password, encryption_key)
    password_hash = hashlib.sha256(encrypted_password).hexdigest()
    with open("passwords.txt", "a") as f:
        f.write(f"{domain}:{username}:{encryption_key}:{encrypted_password}:{password_hash}\n")

def encrypt_password(password, key):

    return bytes(password, 'utf-8')

def retrieve_password(domain):
    with open("passwords.txt", "r") as f:
        for line in f:
            entry = line.strip().split(":")
            if entry[0] == domain:
                encryption_key = entry[2]
                encrypted_password = entry[3]
                if authenticate_master_key():
                    decrypted_password = decrypt_password(encrypted_password, encryption_key)
                    return decrypted_password
                else:
                    return "Master key authentication failed."
    return "Domain not found."

def decrypt_password(encrypted_password, key):

    return encrypted_password

def add_password():
    domain = input("Enter domain: ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    store_password(domain, username, password)
    print("Password added successfully.")

def get_password():
    domain = input("Enter domain: ")
    print(retrieve_password(domain))

def edit_master_key_shell():
    edit_master_key()

if __name__ == "__main__":
    if not os.path.exists("passwords.txt"):
        open("passwords.txt", "a").close()

    if not os.path.exists("master_key.txt"):
        create_master_key()

    choice = input("Choose an option:\n1. Add a new password\n2. Retrieve an existing password\n3. Edit master key\n")

    if choice == "1":
        add_password()
    elif choice == "2":
        get_password()
    elif choice == "3":
        edit_master_key_shell()
    else:
        print("Invalid choice.")

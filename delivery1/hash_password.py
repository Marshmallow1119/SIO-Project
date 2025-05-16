import hashlib

def hash_password(password):
    # Hash the password using SHA-256
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed

if __name__ == "__main__":
    # Input password
    password = input("Enter password to hash: ")
    hashed_password = hash_password(password)
    print(f"Hashed password: {hashed_password}")

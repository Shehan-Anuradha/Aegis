from cryptography.fernet import Fernet

# Generate a new secret key
key = Fernet.generate_key()
print("SECRET_KEY =", key)

cipher = Fernet(key)

# Replace with your chosen password
password = b"enter your key"

encrypted = cipher.encrypt(password)
print("ENCRYPTED_PASSWORD =", encrypted)

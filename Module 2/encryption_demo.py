from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os


# USER INPUT

user_message = input("Enter a message to encrypt: ").encode()


# SYMMETRIC (AES) DEMO

print("\n=== SYMMETRIC ENCRYPTION (AES) DEMO ===")

# Generate a random 256-bit AES key and IV
aes_key = os.urandom(32)
iv = os.urandom(16)

print(f"Original Message: {user_message}")

# Encrypt
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(user_message) + encryptor.finalize()

print(f"AES Key: {aes_key.hex()}")
print(f"IV: {iv.hex()}")
print(f"Ciphertext: {ciphertext.hex()}")

# Decrypt
decryptor = cipher.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()
print(f"Decrypted Message: {decrypted}")



# ASYMMETRIC (RSA) DEMO

print("\n=== ASYMMETRIC ENCRYPTION (RSA) DEMO ===")

# Generate RSA public/private keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

print(f"Original Message: {user_message}")

# Encrypt with public key
ciphertext_rsa = public_key.encrypt(
    user_message,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

print(f"RSA Public Key (n): {public_key.public_numbers().n}")
print(f"Ciphertext: {ciphertext_rsa.hex()}")

# Decrypt with private key
decrypted_rsa = private_key.decrypt(
    ciphertext_rsa,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

print(f"Decrypted Message: {decrypted_rsa}")
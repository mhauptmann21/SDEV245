import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def sha256_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of given bytes."""
    return hashlib.sha256(data).hexdigest()

def aes_encrypt_decrypt(data: bytes):
    """Encrypt and then decrypt data with AES-256-CFB."""
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())

    # Encrypt
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Decrypt
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    return aes_key, iv, ciphertext, decrypted

def main():
    print("=== Hash + Encrypt + Decrypt Demo ===")
    choice = input("(1) Enter a message (2) Encrypt a file: ").strip()

    if choice == "1":
        message = input("Enter your message: ").encode("utf-8")
        original_hash = sha256_bytes(message)
        print(f"\nOriginal SHA-256: {original_hash}")

        # Encrypt + Decrypt
        aes_key, iv, ciphertext, decrypted = aes_encrypt_decrypt(message)

        print(f"AES Key: {aes_key.hex()}")
        print(f"IV: {iv.hex()}")
        print(f"Ciphertext (hex): {ciphertext.hex()}")
        print(f"Decrypted message: {decrypted.decode('utf-8')}")

        # Verify integrity
        decrypted_hash = sha256_bytes(decrypted)
        print(f"Decrypted SHA-256: {decrypted_hash}")
        print("Integrity check:", "PASS!" if decrypted_hash == original_hash else "FAIL!")

    elif choice == "2":
        path = input("Enter file path: ").strip()
        if not os.path.isfile(path):
            print("File not found.")
            return
        with open(path, "rb") as f:
            file_data = f.read()

        original_hash = sha256_bytes(file_data)
        print(f"\nOriginal SHA-256: {original_hash}")

        # Encrypt + Decrypt
        aes_key, iv, ciphertext, decrypted = aes_encrypt_decrypt(file_data)

        print(f"AES Key: {aes_key.hex()}")
        print(f"IV: {iv.hex()}")
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        print(f"Decrypted length: {len(decrypted)} bytes")

        # Verify integrity
        decrypted_hash = sha256_bytes(decrypted)
        print(f"Decrypted SHA-256: {decrypted_hash}")
        print("Integrity check:", "PASS!" if decrypted_hash == original_hash else "FAIL!")

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()

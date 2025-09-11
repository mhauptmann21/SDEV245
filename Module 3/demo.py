import hashlib
import os
import shutil
import subprocess
import sys
from getpass import getpass
from pathlib import Path
from typing import Tuple

def sha256_str (s: str) -> str:
    return hashlib.sha256(s.encode ("utf-8")).hexdigest()

USERS = {
    # username = (sha256(password), role)
    "admin" : (sha256_str("admin123"), "admin"),
    "grace" : (sha256_str("userpass"), "user"),
}

# Authentication / RBAC
def login() -> Tuple[str, str]:
    print("=== Login ===")
    username = input("Username: ").strip()
    password = getpass("Password: ")
    rec = USERS.get(username)
    if not rec:
        print("Invalid username.\n")
        sys.exit(1)
    stored_hash, role = rec
    if sha256_str(password) != stored_hash:
        print("Invalid password.\n")
        sys.exit(1)
    print(f"Welcome, {username}! Role: {role}\n")
    return username, role

def require_role (required: str, actual: str):
    if actual != required:
        raise PermissionError (f"This action requires role '{required}'. Your role '{actual}")

def sha256_file (path: str) -> str:
    h = hashlib.sha256()
    with open (path, "rb") as f:
        for chunk in iter (lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def action_sha256_menu():
    print("=== SHA-256 HASH ===")
    choice = input("(1) Hash STRING (2) Hash FILE: ").strip()
    if choice == "1":
        text = input ("Enter text: ")
        print("SHA-256: ", sha256_str(text))
    elif choice == "2":
        path = input("Path to file: ").strip()
        if not os.path.isfile(path):
            print("File not found.")
            return
        print("SHA-256: ", sha256_file(path))
    else:
        print("Invalid choice.")

# Caesar Cipher
def caesar_shift_char(c: str, shift: int) -> str:
    if "a" <= c <= "z":
        return chr((ord(c) - 97 + shift) % 26 + 97)
    if "A" <= c <= "Z":
        return chr((ord(c) - 65 + shift) % 26 + 65)
    return c

def caesar(text: str, shift: int) -> str:
    return "".join(caesar_shift_char(c, shift) for c in text)

def action_caesar_menu():
    print("== Caesar Cipher ==")
    mode = input("(E)ncrypt or (D)ecrypt? ").strip().lower()
    try:
        shift = int(input("Shift (e.g., 3): ").strip())
    except ValueError:
        print("Shift must be integer.")
        return
    text = input("Input text: ")

    if mode.startswith("e"):
        print("Ciphertext: ", caesar(text, shift))
    elif mode.startswith("d"):
        print("plaintext: ", caesar(text, shift))
    else:
        print("Invalid mode.")

# Digital Signatures via OpenSSL (RSA)
OPENSSL = shutil.which("oppenssl")

def ensure_openssl():
    if not OPENSSL:
        print("OpenSSL not found on PATH. Please install OPENSSL.")
        sys.exit(1)

KEY_DIR = Path("./keys")
PRIV_KEY = KEY_DIR / "rsa_private.pem"
PUB_KEY = KEY_DIR / "rsa_public.pem"

def generate_keys_if_missing():
    KEY_DIR.mkdir(exist_ok = True)
    if not PRIV_KEY.exists():
        # Generate 2048-bit RSA Private Key
        subprocess.run([OPENSSL, "genrsa", "-out", str(PRIV_KEY),
                         "2048"], check = True)
    
    if not PUB_KEY.exists():
        # Extract public key
        subprocess.run([OPENSSL, "rsa", "-in", str(PRIV_KEY),
                         "-pubout", "-out", str(PUB_KEY)], check = True)

def sign_file(input_path: str, sig_path: str):
    # Use SHA@%^ digest and RSA private key
    subprocess.run([OPENSSL, "dgst", "-sha256", "-sign", str(PRIV_KEY),
                     "-out", sig_path, input_path], check = True)

def verify_file(input_path: str, sig_path: str) -> bool:
    # Verify signature using public key
    res = subprocess.run([OPENSSL, "dgst", "-sha256", "verify", str(PUB_KEY),
                           "-signature", sig_path, input_path],
                             capture_output = True, text  = True)
    return "Verified OK" in res.stdout

def action_signature_menu(role: str):
    print("== Digital Signatures (RSA via OpenSSL) ==")
    ensure_openssl()
    generate_keys_if_missing()

    print("(1) Sign a file (admin only)\n(2) Verify a signature\n(3) Show key locations")
    choice = input("Choose: ").strip()

    if choice == "1":
        # Admin-only operation
        try:
            require_role("Admin", role)
        except PermissionError as e:
            print(e)
            return
        path = input("Path to file to sign: ").strip()
        if not os.path.isfile(path):
            print("File not found.")
            return
        sig = input("Output signature path(e.g., file.sig): ").strip() or "signature.sig"
        sign_file(path, sig)
        print(f"Signature written to: {sig}")
    elif choice == "2":
        path = input("Path to original file: ").strip()
        sig = input("Path to signature file: ").strip()
        if not os.path.isfile(path) or not os.path.isfile(sig):
            print("File/signature not found.")
            return
        ok = verify_file(path, sig)
        print("Verification: ", "SUCCESS (Valid Signature)" if ok else "FAILED (Invalid Signature)")
    elif choice == "3":
        print(f"Private Key: {PRIV_KEY.resolve()}")
        print(f"Public Key: {PUB_KEY.resolve()}")
    else:
        print("Invalid choice.")

    
    # Menu
def main():
    user, role = login()

    while True:
        print("\n=== Main Menu ===")
        print("1) SHA-256 Hash (string/file)")
        print("2) Caesar Cipher (encrypt/decrypt)")
        print("3) Digital Signatures (OpenSSL)")
        print("4) Quit")
        choice = input("Choose and option: ").strip()

        if choice == "1":
            action_sha256_menu()
        elif choice == "2":
            action_caesar_menu()
        elif choice == "3":
            action_signature_menu(role)
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")    

if __name__ == "__main__":
    try:
        main()
    except PermissionError as e:
        print("Permission error: ", e)
    except subprocess.CalledProcessError as e:
        print("An OpenSSL command failed: ", e)
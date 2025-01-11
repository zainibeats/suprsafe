import os
import sys
import secrets
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from decrypt import decrypt_files_in_directory
from utils import (
    create_message_window,
    secure_delete,
    prompt_for_main_key,
    set_password,
    get_stored_password_hash,
    check_password,
    store_salt,
)

# New account password setup
def setup_password():
    if not os.path.exists("password_hash.bin"):
        set_password() # Call function in utils.py

# Prompt for account password during each session
def prompt_for_password():
    stored_hash = get_stored_password_hash()

    if stored_hash is None:
        print("No password set up. Exiting program.")
        sys.exit(1)

    attempts = 0
    while attempts < 3:
        password = input("Enter your account password: ")

        if check_password(stored_hash, password):
            return  # Password correct, exit the function
    
        attempts += 1
        print(f"Invalid password. {3 - attempts} attempt(s) remaining.")

    print("Too many failed attempts. Exiting.")
    sys.exit(1)

# Encrypt the AES key and IV with the main key
def encrypt_aes_key_and_iv(aes_key, iv, main_key):
    # Encrypt AES key with the main key using ECB mode
    nonce = os.urandom(16)  # Generate a 16-byte nonce (128 bits)
    cipher = Cipher(algorithms.AES(main_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    data = aes_key + iv  # Combine AES key and IV for encryption
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, tag, nonce

# Function to encrypt a file
def encrypt_file(file_path, aes_key, iv):
    nonce = os.urandom(16) #generate nonce for file encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    
    return ciphertext, tag, nonce #return nonce as well

# Encrypt all files in the directory in which this program ran in
def encrypt_files_in_directory(directory):
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    account_password = getpass.getpass("Enter your account password: ")
    stored_hash = get_stored_password_hash()

    if stored_hash is None:
        print("No password set up. Exiting program.")
        sys.exit(1)

    if not check_password(stored_hash, account_password):
        print("Incorrect password. Exiting.")
        sys.exit(1)

    main_key = prompt_for_main_key()
    ciphertext, tag, nonce = encrypt_aes_key_and_iv(aes_key, iv, main_key)
    keys_dir = os.path.join(directory, 'keys_ivs')
    os.makedirs(keys_dir, exist_ok=True)

    salt = secrets.token_bytes(16)
    store_salt(salt)

    with open(os.path.join(keys_dir, 'encrypted_keys_ivs.bin'), 'wb') as f:
        f.write(ciphertext)
        f.write(tag)
        f.write(nonce)
        
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if filename in ["main.py", "decrypt.py", "utils.py", "keys_ivs", "password_hash.bin", "SuprSafe.exe"] or os.path.isdir(file_path):
            #print(f"Skipping {filename}") # Debugging
            continue

        # Encrypt file
        ciphertext, tag, nonce = encrypt_file(file_path, aes_key, iv)
        
        # Write encrypted files
        encrypted_file_path = file_path + '.enc'
        tag_file_path = file_path + ".enc.tag"
        nonce_file_path = file_path + ".enc.nonce"
        try:
            with open(encrypted_file_path, 'wb') as enc_file:
                enc_file.write(ciphertext)
            with open(tag_file_path, 'wb') as tag_file:
                tag_file.write(tag)
            with open(nonce_file_path, 'wb') as nonce_file:
                nonce_file.write(nonce)

            secure_delete(file_path)
        except Exception as e:
            print(f"Error encrypting {file_path}: {e}")

            # Cleanup partial files if an error occurs
            for temp_file in [encrypted_file_path, tag_file_path, nonce_file_path]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            raise e

    # Encrypt the keys_ivs directory using account password
    encrypt_directory_with_password(keys_dir, account_password)

    create_message_window("Encryption completed! Don't lose your main key or account password.")

# Encrypt the keys_ivs directory with the account password
def encrypt_directory_with_password(directory, password):
    # Generate and store salt securely
    salt = secrets.token_bytes(16)
    store_salt(salt)

    # Use PBKDF2 to derive the key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode())
    #print(f"Directory '{directory}' encrypted with password-derived key!") # Debugging

# Function that is called upon launching program
def main():
    # Display the welcome message
    print("Welcome to SuprSafe!\n")

    # Check if account password is set up
    setup_password()

    # Ask the user for the mode: 'e' for encryption or 'd' for decryption
    action = input("Choose action: (e) Encrypt or (d) Decrypt: ").strip().lower()

    if action == 'e':
        current_dir = os.getcwd()
        encrypt_files_in_directory(current_dir)
    elif action == 'd':
        current_dir = os.getcwd()
        decrypt_files_in_directory(current_dir)
    else:
        print("Invalid choice. Please choose 'e' for encryption or 'd' for decryption.")
        return

if __name__ == "__main__":
    main()

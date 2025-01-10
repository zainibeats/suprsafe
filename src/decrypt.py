import os
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from utils import (
    secure_delete,
    prompt_for_main_key,
    derive_key,
    get_stored_salt,
    decrypt_aes_key_and_iv,
    get_stored_password_hash,
    check_password,
)

# Decrypt the keys_ivs directory using the account password
def decrypt_keys_ivs_directory(directory, password):
    directory = os.path.join(directory, 'keys_ivs')

    # Use the utility function to retrieve the salt from the correct location
    salt = get_stored_salt()

    # Derive the key from the password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,  # Must be 32 for AES-256
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode())
    print("Directory decrypted and password verified!")
    return derived_key

# Function that decrypts a file
def decrypt_file(file_path, aes_key, iv, tag, nonce):
    with open(file_path, 'rb') as f:
        ciphertext = f.read()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend()) #add nonce to cipher
    decryptor = cipher.decryptor()
    try:
        data = decryptor.update(ciphertext) + decryptor.finalize()
        return data
    except Exception as e:
        print(f"Decryption Error: {e}")
        return None

    # print(f"File {file_path} decrypted to {decrypted_file_path}")

# Decrypt all files in the directory in which this program ran in
def decrypt_files_in_directory(directory):
    account_password = getpass.getpass("Enter your account password to unlock keys: ")
    
    # Verify the account password against the stored hash
    stored_hash = get_stored_password_hash()
    if stored_hash is None:
        print("No password set up. Exiting program.")
        return

    # Check if the entered password matches the stored hash
    if not check_password(stored_hash, account_password):
        print("Incorrect password. Exiting.")
        return

    print("Password verified!")

    # Only proceed to the next steps if the password is correct
    keys_dir = os.path.join(directory, 'keys_ivs')
    salt = get_stored_salt()
    derived_key = derive_key(account_password.encode(), salt, 100000, 32) #encode password
    main_key = prompt_for_main_key()

    try:
        with open(os.path.join(directory, 'keys_ivs', 'encrypted_keys_ivs.bin'), 'rb') as f:
            data = f.read()
        ciphertext = data[:-32]
        tag = data[-32:-16]
        nonce = data[-16:]
    except FileNotFoundError:
        print("Error: Encrypted keys file not found.")
        return

    # Call the function to decrypt the AES key and IV
    #main_key = prompt_for_main_key()
    aes_key, iv = decrypt_aes_key_and_iv(ciphertext, tag, nonce, main_key)
    #print(f"AES Key: {aes_key}, Length: {len(aes_key)}")

    if aes_key is None:
        return

    # Decrypt each file in the directory
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)

        # Skip directories and non-encrypted files
        if os.path.isdir(file_path) or not filename.endswith(".enc"):
            print(f"Skipping {filename}")
            continue

        # Remove the ".enc" extension from the file path only if it ends with ".enc"
        if filename.endswith('.enc'):
            base_file_path = file_path[:-4]  # Removes ".enc"
        else:
            base_file_path = file_path  # No stripping needed if filename doesn't end with ".enc"

        # Find the corresponding .enc.tag and .enc.nonce files
        tag_file_path = base_file_path + ".enc.tag"
        nonce_file_path = base_file_path + ".enc.nonce"

        # Debugging: Print the tag and nonce file paths to check where it's looking
        print(f"Looking for tag file: {tag_file_path}")
        print(f"Looking for nonce file: {nonce_file_path}")

        # Check if both the tag and nonce files exist
        if not os.path.exists(tag_file_path) or not os.path.exists(nonce_file_path):
            print(f"Tag or Nonce file not found for {filename}. Skipping decryption.")
            continue  # Skip this file and move on to the next one

        # Read the tag and nonce files if they exist
        try:
            with open(tag_file_path, 'rb') as tag_file:
                tag = tag_file.read()
            with open(nonce_file_path, 'rb') as nonce_file:
                nonce = nonce_file.read()
        except FileNotFoundError:
            print(f"Tag or Nonce file not found for {filename}. Skipping decryption.")
            continue  # Skip this file and move on to the next one

        # Now decrypt the file with aes_key, iv, tag, and nonce
        decrypted_data = decrypt_file(file_path, aes_key, iv, tag, nonce)
        if decrypted_data is None:
            print(f"Decryption failed for {filename}.")
            continue  # Skip to the next file if decryption failed

        # Write the decrypted data to a new file
        decrypted_file_path = base_file_path  # Use the base file path without the .enc extension
        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        # Securely delete the original encrypted file
        try:
            secure_delete(file_path)
            secure_delete(tag_file_path)
            secure_delete(nonce_file_path)
            print(f"Deleted encrypted files for {filename}.")
        except Exception as e:
            print(f"Error deleting files for {filename}: {e}")

if __name__ == "__main__":
    current_dir = os.getcwd()
    decrypt_files_in_directory(current_dir)

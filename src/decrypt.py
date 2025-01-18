import os
import getpass
import sys
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
    create_message_window,
    get_directory_from_user,
    start_loading_animation,
    stop_loading_animation,
    create_temp_state,
    cleanup_temp_state,
    handle_interrupt,
    wipe_encrypted_files,
    _wipe_on_fail,
    load_security_settings,
)
import threading
import time
import signal

# Decrypt keys directory using account password
def decrypt_keys_ivs_directory(directory, password):
    directory = os.path.join(directory, 'keys_ivs')
    salt = get_stored_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode())
    print("Directory decrypted and password verified!")
    return derived_key

# Decrypt a single file using AES-GCM
def decrypt_file(file_path, aes_key, iv, tag, nonce):
    with open(file_path, 'rb') as f:
        ciphertext = f.read()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        data = decryptor.update(ciphertext) + decryptor.finalize()
        return data
    except Exception as e:
        print(f"Decryption Error: {e}")
        return None

# Decrypt all files in selected directory
def decrypt_files_in_directory(directory):
    animation_thread = None
    try:
        create_temp_state('decrypt', directory)
        # Add signal handlers for interrupts
        signal.signal(signal.SIGINT, lambda s, f: handle_interrupt(directory))
        
        # Load security settings at start
        load_security_settings()
        
        stored_hash = get_stored_password_hash()
        if stored_hash is None:
            print("No password set up. Restarting program for setup...")
            from main import main  # Import here to avoid circular import
            main()
            return

        attempts = 0
        while attempts < 3:
            account_password = getpass.getpass("Enter your account password to unlock keys: ")
            
            if check_password(stored_hash, account_password):
                keys_dir = os.path.join(directory, 'keys_ivs')
                salt = get_stored_salt()
                derived_key = derive_key(account_password.encode(), salt, 100000, 32)

                with open(os.path.join(directory, 'keys_ivs', 'encrypted_keys_ivs.bin'), 'rb') as f:
                    data = f.read()
                ciphertext = data[:-32]
                tag = data[-32:-16]
                nonce = data[-16:]

                main_key = prompt_for_main_key(check_existing=True, existing_key_data=(ciphertext, tag, nonce), directory=directory)

                try:
                    # Start the loading animation
                    animation_thread = start_loading_animation("Decrypting files")

                    # Decrypt the AES key and IV
                    aes_key, iv = decrypt_aes_key_and_iv(ciphertext, tag, nonce, main_key)
                    if aes_key is None:
                        return
                        
                    # Decrypt each file in the directory
                    for filename in os.listdir(directory):
                        file_path = os.path.join(directory, filename)

                        # Skip directories and non-encrypted files
                        if os.path.isdir(file_path) or not filename.endswith(".enc"):
                            #print(f"Skipping {filename}") # Debugging
                            continue

                        # Remove the ".enc" extension from the file path only if it ends with ".enc"
                        if filename.endswith('.enc'):
                            base_file_path = file_path[:-4]  # Removes ".enc"
                        else:
                            base_file_path = file_path  # No stripping needed if filename doesn't end with ".enc"

                        # Find the corresponding .enc.tag and .enc.nonce files
                        tag_file_path = base_file_path + ".enc.tag"
                        nonce_file_path = base_file_path + ".enc.nonce"

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
                        except Exception as e:
                            print(f"Error deleting files for {filename}: {e}")
                    
                    # Stop the animation
                    stop_loading_animation(animation_thread)
                    
                    # Create a message window to inform the user that the files are now decrypted
                    create_message_window("Your files are now decrypted. Don't lose your main key or account password.")
                    return # Exit the function after successful decryption
                
                # If the encrypted keys file is not found, print an error message and exit the function
                except FileNotFoundError:
                    stop_loading_animation(animation_thread)
                    print("Error: Encrypted keys file not found.")
                    return
            
            # If the password is incorrect, print an error message and increment the attempt counter
            attempts += 1
            if attempts < 3:
                print(f"Invalid password. {3 - attempts} attempt(s) remaining.")
            else:
                print("Too many failed attempts.")
                if _wipe_on_fail:
                    print("Wiping encrypted files...")
                    wipe_encrypted_files(directory)
                sys.exit(1)

        # If the user has made too many attempts, print an error message and exit the program
        print("Too many failed attempts. Exiting.")
        sys.exit(1)

    except Exception as e:
        print(f"\nDecryption error: {e}")
    finally:
        cleanup_temp_state(directory)
        if animation_thread:
            stop_loading_animation(animation_thread)

# Main entry point for decrypting files
if __name__ == "__main__":
    directory = get_directory_from_user()
    decrypt_files_in_directory(directory)

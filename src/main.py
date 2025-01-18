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
    get_directory_from_user,
    start_loading_animation,
    stop_loading_animation,
    create_temp_state,
    cleanup_temp_state,
    handle_interrupt,
    configure_wipe_on_fail,
    load_security_settings,
    wipe_encrypted_files,
    security_settings,
)

# Initialize account password on first program run
def setup_password():
    if not os.path.exists("password_hash.bin"):
        set_password()

# Verify account password with 3-attempt limit
def prompt_for_password():
    stored_hash = get_stored_password_hash()

    if stored_hash is None:
        print("No password set up. Exiting program.")
        sys.exit(1)

    attempts = 0
    while attempts < 3:
        password = input("Enter your account password: ")

        if check_password(stored_hash, password):
            return
    
        attempts += 1
        print(f"Invalid password. {3 - attempts} attempt(s) remaining.")

    print("Too many failed attempts. Exiting.")
    sys.exit(1)

# Encrypt AES key and IV pair using main key with GCM mode
def encrypt_aes_key_and_iv(aes_key, iv, main_key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(main_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    data = aes_key + iv
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, tag, nonce

# Encrypt single file using AES-GCM with provided key and IV
def encrypt_file(file_path, aes_key, iv):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    
    return ciphertext, tag, nonce

# Main encryption function - handles directory selection, password verification, and file encryption
def encrypt_files_in_directory(directory):
    animation_thread = None
    try:
        create_temp_state('encrypt', directory)
        # Add signal handlers for interrupts
        import signal
        signal.signal(signal.SIGINT, lambda s, f: handle_interrupt(directory))
        
        # Load security settings at start
        load_security_settings()
        
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        stored_hash = get_stored_password_hash()

        if stored_hash is None:
            print("No password set up. Restarting program for setup...")
            main()  # Restart the program to set up password
            return

        attempts = 0
        while attempts < 3:
            account_password = getpass.getpass("Enter your account password: ")
            
            if check_password(stored_hash, account_password):
                main_key = prompt_for_main_key()
                animation_thread = start_loading_animation("Encrypting files")
                
                try:
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

                    stop_loading_animation(animation_thread)
                    create_message_window("Encryption completed! Don't lose your main key or account password.")
                    return
                except Exception as e:
                    print(f"Error during encryption: {e}")
                finally:
                    stop_loading_animation(animation_thread)
                return
            
            attempts += 1
            if attempts < 3:
                print(f"Invalid password. {3 - attempts} attempt(s) remaining.")
            else:
                print("Too many failed attempts.")
                if security_settings['wipe_on_fail']:
                    print("Wiping encrypted files...")
                    wipe_encrypted_files(directory)
                sys.exit(1)
                
    except Exception as e:
        print(f"\nEncryption error: {e}")
    finally:
        cleanup_temp_state(directory)

# Encrypt keys_ivs directory using derived key from account password
def encrypt_directory_with_password(directory, password):
    salt = secrets.token_bytes(16)
    store_salt(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode())

# Main program entry point - handles user interaction and operation selection
def main():
    print("Welcome to SuprSafe!\n")
    setup_password()
    
    # Load security settings
    load_security_settings()
    
    if security_settings['wipe_on_fail']:
        print("SuprSafe+ Mode: ENABLED")
    else:
        print("SuprSafe+ Mode: DISABLED")

    if input("Would you like to configure SuprSafe+ Mode? (y/n): ").lower().strip() == 'y':
        configure_wipe_on_fail()

    action = input("Choose action: (e) Encrypt or (d) Decrypt: ").strip().lower()

    if action in ['e', 'd']:
        # Get directory from user instead of using current directory
        directory = get_directory_from_user()
        
        if action == 'e':
            encrypt_files_in_directory(directory)
        else:
            decrypt_files_in_directory(directory)
    else:
        print("Invalid choice. Please choose 'e' for encryption or 'd' for decryption.")
        return

# Main entry point for program
if __name__ == "__main__":
    main()

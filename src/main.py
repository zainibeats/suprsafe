import os
import sys
import secrets
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore, Style
from decrypt import decrypt_files_in_directory
from utils import (
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
    configure_wipe_files_after_max_attempts,
    load_security_settings,
    wipe_encrypted_files,
    security_settings,
)

# Initialize colorama
init(autoreset=True)

# Verify account password with 3-attempt limit
def prompt_for_password():
    stored_hash = get_stored_password_hash()

    if stored_hash is None:
        print(f"{Fore.RED}No password set up. Exiting program.")
        sys.exit(1)

    attempts = 0
    while attempts < 3:
        password = getpass.getpass(f"{Fore.CYAN}Enter your account password: ")

        if check_password(stored_hash, password):
            return
    
        attempts += 1
        print(f"{Fore.RED}Invalid password. {3 - attempts} attempt(s) remaining.")

    print(f"{Fore.RED}Too many failed attempts. Exiting.")
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
            print(f"{Fore.RED}No password set up. Restarting program for setup...")
            main()  # Restart the program to set up password
            return

        attempts = 0
        while attempts < 3:
            account_password = getpass.getpass(f"{Fore.CYAN}Enter your account password: ")
            
            if check_password(stored_hash, account_password):
                main_key = prompt_for_main_key()
                animation_thread = start_loading_animation(f"{Fore.CYAN}Encrypting files")
                
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
                        if filename in ["main.py", "decrypt.py", "utils.py", "keys_ivs", "SuprSafe.exe"] or os.path.isdir(file_path):
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
                    print(f"{Fore.GREEN}Encryption completed successfully!")
                    return
                except Exception as e:
                    print(f"{Fore.RED}Error during encryption: {e}")
                finally:
                    stop_loading_animation(animation_thread)
                return
            
            attempts += 1
            if attempts < 3:
                print(f"{Fore.RED}Invalid password. {3 - attempts} attempt(s) remaining.")
            else:
                print(f"{Fore.RED}Too many failed attempts.")
                if security_settings['wipe_files_after_max_attempts']:
                    print(f"{Fore.RED}Wiping encrypted files...")
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
    print(f"{Fore.CYAN}Welcome to SuprSafe!\n")
    
    # Only set up password if no password hash exists
    if get_stored_password_hash() is None:
        set_password()
    
    # Load security settings
    load_security_settings()
    
    if security_settings['wipe_files_after_max_attempts']:
        print(f"SuprSafe+ Mode: {Fore.GREEN}ENABLED")
    else:
        print(f"SuprSafe+ Mode: {Fore.RED}DISABLED")

    if input(f"{Fore.CYAN}Would you like to configure SuprSafe+ Mode? (y/n): ").lower().strip() == 'y':
        configure_wipe_files_after_max_attempts()

    while True:  # Keep asking until valid input is received
        action = input(f"{Fore.CYAN}Choose action: (e) Encrypt or (d) Decrypt: ").strip().lower()

        if action == 'q':
            print(f"{Fore.YELLOW}Exiting SuprSafe. Goodbye!")
            sys.exit(0)
        elif action in ['e', 'd']:
            # Get directory from user instead of using current directory
            directory = get_directory_from_user()
            if directory is None:
                continue  # Go back to action selection if no directory selected
            
            if action == 'e':
                encrypt_files_in_directory(directory)
            else:
                decrypt_files_in_directory(directory)
            break  # Exit the loop after successful operation
        else:
            print(f"{Fore.RED}Invalid choice. Please choose 'e' for encryption, 'd' for decryption, or 'q' to quit.")

# Main entry point for program
if __name__ == "__main__":
    main()

# type: ignore
import os
import random
import sys
import hashlib
import tkinter as tk
from tkinter import simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter import filedialog
import threading
import time
import getpass

# File where the password hash will be stored
PASSWORD_FILE = "password_hash.bin"

# Global animation flag
_stop_animation = False

# Global security settings
SECURITY_CONFIG_FILE = "security_config.bin"
_wipe_on_fail = False  # Default to False for safety

# Derives a key from a password using PBKDF2HMAC
def derive_key(password, salt, iterations, key_len):
  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=key_len,
      salt=salt,
      iterations=iterations,
  )
  return kdf.derive(password)

# Hash the password using bcrypt
def create_password_hash(password):
    password = password.encode()
    salt = os.urandom(32)  # Generate a 32-byte salt
    hash_obj = hashlib.pbkdf2_hmac(
        'sha256',
        password,
        salt,
        100000  # Number of iterations
    )
    # Store salt and hash together
    return salt + hash_obj

# Check if the entered password matches the stored hash
def check_password(stored_hash, password):
    salt = stored_hash[:32]  # First 32 bytes are salt
    stored_hash = stored_hash[32:]  # Rest is the hash
    hash_obj = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000  # Same number of iterations as above
    )
    return hash_obj == stored_hash

# On first startup, set a password for the user
def set_password():
    password = input("Please set your account password: ")
    confirm_password = input("Confirm your password: ")

    if password != confirm_password:
        print("Passwords do not match. Please try again.")
        return set_password()
    
    password_hash = create_password_hash(password)

    with open(PASSWORD_FILE, 'wb') as f:
        f.write(password_hash)

    print("Password set successfully.")

# Get the stored password hash from the file
def get_stored_password_hash():
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'rb') as f:
            return f.read()
        
    else:
        return None

# Save the salt to the keys_ivs folder for future decryption
def store_salt(salt):
    salt_dir = os.path.join(os.getcwd(), 'salt_files')
    os.makedirs(salt_dir, exist_ok=True)  # Create the directory if it doesn't exist
    salt_path = os.path.join(salt_dir, 'salt.bin')
    try:
        with open(salt_path, 'wb') as f:
            f.write(salt)
        #print(f"Salt stored at {salt_path}") # Debugging
    except OSError as e:
        print(f"Failed to write salt: {e}")
        sys.exit(1)

# Look for and read stored salt from program files
def get_stored_salt():
    salt_dir = os.path.join(os.getcwd(), 'salt_files')
    salt_path = os.path.join(salt_dir, 'salt.bin')
    if os.path.exists(salt_path):
        with open(salt_path, 'rb') as f:
            return f.read()
    else:
        print("Salt file not found. Ensure the program has run at least once to generate it.")
        sys.exit(1)

# Delete the old files after encryption/decryption
def secure_delete(file_path, passes=4):
    with open(file_path, 'r+b') as f:
        length = os.path.getsize(file_path)
        for _ in range(passes):
            f.seek(0)
            f.write(bytearray(random.getrandbits(8) for _ in range(length)))
    os.remove(file_path)

# Function to create floating gui window
def create_message_window(message):
    root = tk.Tk()
    root.title("Message")

    # Set the window to always stay on top
    root.attributes("-topmost", 1)

    # Get screen width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Get window width and height
    window_width = 400
    initial_height = 100

    # Calculate position to center the window
    position_top = int(screen_height / 2 - initial_height / 2)
    position_right = int(screen_width / 2 - window_width / 2)

    # Set the position of the window
    root.geometry(f'{window_width}x{initial_height}+{position_right}+{position_top}')

    # Create a label with the wrapped message
    label = tk.Label(root, text=message, wraplength=window_width - 20, padx=10, pady=10)
    label.pack()

    # Update the window size after the text has been wrapped
    label.update_idletasks()  # Ensure the widget has been rendered before measuring its height
    window_height = label.winfo_height()  # Get the height of the wrapped text

    # Set the window's geometry with the new height
    root.geometry(f'{window_width}x{window_height + 80}+{position_right}+{position_top}')  # Add some padding

    # Add the Close button
    tk.Button(root, text="Close", command=root.quit).pack()

    # Handle the close button (X) click by binding the protocol
    root.protocol("WM_DELETE_WINDOW", root.quit)

    root.mainloop()

# Creates a temporary state file with minimal info
def create_temp_state(operation_type, directory):
    state_file = os.path.join(os.path.dirname(directory), '.suprsafe_temp')
    try:
        with open(state_file, 'w') as f:
            f.write(f"{operation_type}:{directory}")
    except Exception:
        pass  # Fail silently for security

# Removes the temporary state file
def cleanup_temp_state(directory):
    state_file = os.path.join(os.path.dirname(directory), '.suprsafe_temp')
    try:
        if os.path.exists(state_file):
            secure_delete(state_file)
    except Exception:
        pass  # Fail silently for security

# Cleanup handler for interrupts
def handle_interrupt(directory):
    print("\n\nOperation interrupted. Cleaning up...")
    cleanup_temp_state(directory)
    sys.exit(1)

# Prompt for main key with retry logic and verification
def prompt_for_main_key(check_existing=False, existing_key_data=None, directory=None):
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", 1)
    
    attempts = 0
    while attempts < 3:
        key = simpledialog.askstring("Main Key", "Enter 32-byte main key:")
        
        if key is None:  # User clicked Cancel
            print("\nMain key entry cancelled. Exiting program.")
            if directory:  # Only cleanup if directory is provided
                cleanup_temp_state(directory)
            sys.exit(0)
            
        key = key.strip()  # Strip any whitespace
            
        if len(key) != 32:
            print("Error: The main key must be exactly 32 characters long. Please try again.")
            continue
            
        encoded_key = key.encode()
        
        # If we need to verify against existing key
        if check_existing and existing_key_data:
            try:
                ciphertext, tag, nonce = existing_key_data
                # Try to decrypt with the provided key
                cipher = Cipher(algorithms.AES(encoded_key), modes.GCM(nonce, tag=tag), backend=default_backend())
                decryptor = cipher.decryptor()
                decryptor.update(ciphertext) + decryptor.finalize()
                return encoded_key  # Key is correct
            except Exception:
                attempts += 1
                if attempts < 3:
                    print(f"Invalid main key. {3 - attempts} attempt(s) remaining.")
                    continue
                else:
                    print("Too many failed attempts.")
                    if _wipe_on_fail:
                        print("Wiping encrypted files...")
                        wipe_encrypted_files(directory)
                    sys.exit(1)
        else:
            return encoded_key  # New key, no verification needed
    
    print("Too many failed attempts. Exiting.")
    sys.exit(1)

# Decrypt aes key and iv with main key
def decrypt_aes_key_and_iv(ciphertext, tag, nonce, main_key):
    # Decrypt AES key with the main key using ECB mode
    cipher = Cipher(algorithms.AES(main_key), modes.GCM(nonce, tag=tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Extract AES key and IV
    aes_key = decrypted_data[:32]  # First 32 bytes for AES key
    iv = decrypted_data[32:48]    # Next 16 bytes for IV

    if len(iv) != 16:
        raise ValueError(f"Invalid IV length: {len(iv)} bytes (expected 16 bytes)")

    #print(f"Decrypted AES Key Length: {len(aes_key)} bytes") # Debugging
    return aes_key, iv

# Add this new function to utils.py
def get_directory_from_user():
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    root.attributes("-topmost", 1)
    
    directory = filedialog.askdirectory(
        title="Select Directory",
        initialdir=os.getcwd()  # Start from current directory
    )
    
    if not directory:  # If user cancels selection
        print("\nDirectory selection cancelled. Exiting program.")
        sys.exit(0)  # Exit cleanly
    
    return directory

# Loading animation
def animate_loading(message="Processing"):
    global _stop_animation
    dots = 1
    while not _stop_animation:
        print(f"\r{message}{'.' * dots}", end='', flush=True)
        dots = (dots % 3) + 1
        time.sleep(0.5)

# Start loading animation
def start_loading_animation(message="Processing"):
    global _stop_animation
    _stop_animation = False
    animation_thread = threading.Thread(target=lambda: animate_loading(message))
    animation_thread.daemon = True
    animation_thread.start()
    return animation_thread

# Stop loading animation
def stop_loading_animation(thread):
    global _stop_animation
    _stop_animation = True
    thread.join(timeout=1)
    print('\r' + ' ' * 50 + '\r', end='', flush=True)  # Clear the animation line

# Configure wipe-on-fail security feature
def configure_wipe_on_fail(stored_hash):
    global _wipe_on_fail
    attempts = 0
    while attempts < 3:
        password = getpass.getpass("Enter your account password to modify security settings: ")
        if check_password(stored_hash, password):
            choice = input("Enable delete files on too many failed attempts? (y/n): ").lower().strip()
            _wipe_on_fail = choice == 'y'
            
            # Store the setting securely
            try:
                with open(SECURITY_CONFIG_FILE, 'wb') as f:
                    # Store setting with password hash to prevent tampering
                    setting_bytes = bytes([int(_wipe_on_fail)])
                    f.write(setting_bytes)
                print(f"Security setting {'enabled' if _wipe_on_fail else 'disabled'} successfully.")
                return True
            except Exception:
                print("Error saving security settings.")
                return False
                
        attempts += 1
        if attempts < 3:
            print(f"Invalid password. {3 - attempts} attempt(s) remaining.")
    
    print("Too many failed attempts. Exiting.")
    sys.exit(1)

# Load security settings
def load_security_settings():
    global _wipe_on_fail
    try:
        if os.path.exists(SECURITY_CONFIG_FILE):
            with open(SECURITY_CONFIG_FILE, 'rb') as f:
                setting_bytes = f.read(1)
                _wipe_on_fail = bool(int.from_bytes(setting_bytes, 'big'))
    except Exception:
        _wipe_on_fail = False  # Default to safe setting on error

# Wipe encrypted files in directory
def wipe_encrypted_files(directory):
    try:
        for filename in os.listdir(directory):
            if filename.endswith('.enc'):
                file_path = os.path.join(directory, filename)
                base_file_path = file_path[:-4]
                tag_file_path = base_file_path + ".enc.tag"
                nonce_file_path = base_file_path + ".enc.nonce"
                
                # Securely delete all related files
                for f in [file_path, tag_file_path, nonce_file_path]:
                    if os.path.exists(f):
                        secure_delete(f)
        
        # Also remove the keys directory
        keys_dir = os.path.join(directory, 'keys_ivs')
        if os.path.exists(keys_dir):
            for f in os.listdir(keys_dir):
                secure_delete(os.path.join(keys_dir, f))
            os.rmdir(keys_dir)
            
    except Exception as e:
        print(f"Error during secure wipe: {e}")

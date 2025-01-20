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
from colorama import init, Fore, Style
import secrets

# Initialize colorama
init(autoreset=True)

def get_data_dir():
    """Get the path to the data directory, creating it if it doesn't exist."""
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
    os.makedirs(data_dir, exist_ok=True)
    return data_dir

# File where the password hash will be stored
PASSWORD_FILE = os.path.join(get_data_dir(), "password_hash.bin")

# Global animation flag
_stop_animation = False

# Global security settings
SECURITY_CONFIG_FILE = os.path.join(get_data_dir(), "security_config.bin")
security_settings = {
    'wipe_files_after_max_attempts': False  # If enabled, deletes all encrypted files after too many failed password/key attempts
}

# Add new constants for SuprSafe+ settings
SUPRSAFE_PLUS_PASSWORD_FILE = os.path.join(get_data_dir(), "suprsafe_plus.bin")
_wipe_files_after_max_attempts = False # True = SuprSafe+ Mode enabled

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
    while True:
        password = input(f"{Fore.CYAN}Please set your account password: ")
        if len(password) < 4:
            print(f"{Fore.RED}Password must be at least 4 characters long.")
            continue
            
        confirm_password = input(f"{Fore.CYAN}Confirm your password: ")

        if password != confirm_password:
            print(f"{Fore.RED}Passwords do not match. Please try again.")
            continue
        
        password_hash = create_password_hash(password)

        with open(PASSWORD_FILE, 'wb') as f:
            f.write(password_hash)

        print(f"{Fore.GREEN}Password set successfully.")
        break

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
        print(f"{Fore.RED}Failed to write salt: {e}")
        sys.exit(1)

# Look for and read stored salt from program files
def get_stored_salt():
    salt_dir = os.path.join(os.getcwd(), 'salt_files')
    salt_path = os.path.join(salt_dir, 'salt.bin')
    if os.path.exists(salt_path):
        with open(salt_path, 'rb') as f:
            return f.read()
    else:
        print(f"{Fore.RED}Salt file not found. Ensure the program has run at least once to generate it.")
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
    while attempts < 5:
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
                if attempts < 5:
                    print(f"Invalid main key. {5 - attempts} attempt(s) remaining.")
                    continue
                else:
                    print("Too many failed attempts.")
                    if security_settings['wipe_files_after_max_attempts']:
                        print("Wiping encrypted files...")
                        wipe_encrypted_files(directory)
                    sys.exit(1)
        else:
            return encoded_key  # New key, no verification needed
    
    print("Too many failed attempts. Exiting.")
    sys.exit(1)

# Decrypt aes key and iv with main key
def decrypt_aes_key_and_iv(ciphertext, tag, nonce, main_key):
    try:
        # Decrypt AES key with the main key using ECB mode
        cipher = Cipher(algorithms.AES(main_key), modes.GCM(nonce, tag=tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Extract AES key and IV
        aes_key = decrypted_data[:32]  # First 32 bytes for AES key
        iv = decrypted_data[32:48]    # Next 16 bytes for IV

        if len(iv) != 16:
            raise ValueError(f"Invalid IV length: {len(iv)} bytes (expected 16 bytes)")

        return aes_key, iv
    finally:
        # Securely wipe sensitive data
        if 'decrypted_data' in locals():
            secure_wipe(decrypted_data)
        if 'cipher' in locals():
            del cipher
        if 'decryptor' in locals():
            del decryptor

# Add this new function to utils.py
def get_directory_from_user():
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    root.attributes("-topmost", 1)
    
    try:
        directory = filedialog.askdirectory(
            title="Select Directory",
            initialdir=os.getcwd()  # Start from current directory
        )
        
        # Force focus back to terminal
        if os.name == 'nt':  # Windows
            import win32gui
            import win32con
            hwnd = win32gui.GetForegroundWindow()
            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        
        if not directory:  # If user cancels selection
            print(f"{Fore.YELLOW}No directory selected, returning to main menu.")
            return None
        
        return directory
    finally:
        root.destroy()  # Ensure the root window is destroyed whether directory is selected or not

# Loading animation
def animate_loading(message="Processing"):
    global _stop_animation
    dots = 1
    while not _stop_animation:
        print(f"\r{Fore.CYAN}{message}{'.' * dots}", end='', flush=True)
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

# Set up SuprSafe+ admin password
def setup_suprsafe_plus_password():
    print(f"\n{Fore.CYAN}Set up SuprSafe+ administrator password")
    print(f"{Fore.YELLOW}WARNING: This password controls security settings and should be different from your account password")
    
    while True:
        password = getpass.getpass(f"{Fore.CYAN}Enter SuprSafe+ admin password: ")
        if len(password) < 4:
            print(f"{Fore.RED}Password must be at least 4 characters long.")
            continue
            
        confirm = getpass.getpass(f"{Fore.CYAN}Confirm SuprSafe+ admin password: ")
        
        if password != confirm:
            print(f"{Fore.RED}Passwords do not match. Please try again.")
            continue
        
        password_hash = create_password_hash(password)
        with open(SUPRSAFE_PLUS_PASSWORD_FILE, 'wb') as f:
            f.write(password_hash)
        print(f"{Fore.GREEN}SuprSafe+ admin password set successfully.")
        break

# Get stored SuprSafe+ password hash
def get_stored_suprsafe_plus_hash():
    if os.path.exists(SUPRSAFE_PLUS_PASSWORD_FILE):
        with open(SUPRSAFE_PLUS_PASSWORD_FILE, 'rb') as f:
            return f.read()
    return None

# Configure wipe-files-after-max-attempts with separate admin password
def configure_wipe_files_after_max_attempts():
    stored_hash = get_stored_suprsafe_plus_hash()
    
    if stored_hash is None:
        print(f"{Fore.RED}No SuprSafe+ admin password set.")
        setup_suprsafe_plus_password()
        stored_hash = get_stored_suprsafe_plus_hash()
    
    attempts = 0
    while attempts < 3:
        password = getpass.getpass(f"{Fore.CYAN}Enter SuprSafe+ admin password: ")
        if check_password(stored_hash, password):
            choice = input(f"{Fore.CYAN}Enable SuprSafe+ Mode (wipe files on failed attempts)? (y/n): ").lower().strip()
            previous_state = security_settings['wipe_files_after_max_attempts']
            security_settings['wipe_files_after_max_attempts'] = choice == 'y'
            
            try:
                with open(SECURITY_CONFIG_FILE, 'wb') as f:
                    setting_bytes = bytes([int(security_settings['wipe_files_after_max_attempts'])])
                    f.write(setting_bytes)
                    f.flush()
                    os.fsync(f.fileno())
                print(f"{Fore.YELLOW}SuprSafe+ Mode {'enabled' if security_settings['wipe_files_after_max_attempts'] else 'disabled'} successfully.")
                return True
            except Exception:
                print(f"{Fore.RED}Error saving security settings.")
                security_settings['wipe_files_after_max_attempts'] = previous_state
                return False
                
        attempts += 1
        if attempts < 3:
            print(f"{Fore.RED}Invalid password. {3 - attempts} attempt(s) remaining.")
    
    print(f"{Fore.RED}Too many failed attempts. Exiting.")
    sys.exit(1)

# Initialize security settings on first run
def initialize_security_settings():
    if not os.path.exists(SECURITY_CONFIG_FILE):
        try:
            with open(SECURITY_CONFIG_FILE, 'wb') as f:
                # Initialize to disabled (0)
                f.write(bytes([0]))
                f.flush()  # Force write to disk
                os.fsync(f.fileno())  # Ensure it's written to disk
        except Exception:
            print(f"{Fore.RED}WARNING: Could not initialize security settings.")
            # Don't modify _wipe_files_after_max_attempts, maintain secure state

# Load security settings
def load_security_settings():
    try:
        if os.path.exists(SECURITY_CONFIG_FILE):
            with open(SECURITY_CONFIG_FILE, 'rb') as f:
                setting_bytes = f.read(1)
                if setting_bytes:  # Make sure we have data
                    security_settings['wipe_files_after_max_attempts'] = bool(setting_bytes[0])
                else:
                    print(f"{Fore.RED}WARNING: Security settings file is corrupted.")
                    print(f"{Fore.RED}For security reasons, maintaining previous SuprSafe+ Mode state.")
        else:
            initialize_security_settings()
    except Exception:
        print(f"{Fore.RED}WARNING: Error reading security settings.")
        print(f"{Fore.RED}For security reasons, maintaining previous SuprSafe+ Mode state.")

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

def secure_wipe(data):
    """Securely wipe sensitive data from memory."""
    if isinstance(data, str):
        length = len(data)
        # Overwrite with random data
        for _ in range(3):  # Multiple overwrite passes
            for i in range(length):
                data = data[:i] + chr(secrets.randbelow(256)) + data[i+1:]
    elif isinstance(data, bytes):
        length = len(data)
        # Overwrite with random bytes
        for _ in range(3):  # Multiple overwrite passes
            for i in range(length):
                data = data[:i] + bytes([secrets.randbelow(256)]) + data[i+1:]
    
    return None  # Ensure the data is not accidentally reused

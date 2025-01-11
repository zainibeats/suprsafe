import os
import random
import sys
import bcrypt
import tkinter as tk
from tkinter import simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# File where the password hash will be stored
PASSWORD_FILE = "password_hash.bin"

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
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed

# Check if the entered password matches the stored hash
def check_password(stored_hash, password):
    password = password.encode()
    return bcrypt.checkpw(password, stored_hash)

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

# Ask user to input their main key
def prompt_for_main_key():
    root = tk.Tk()
    root.withdraw() # Hide the main window
    root.attributes("-topmost", 1) # Set the window to always stay on top
    while True:
        key = simpledialog.askstring("Main Key", "Enter 32-byte main key:")
        if len(key) != 32:
            print("Error: The main key must be exactly 32 characters long. Please try again.")
            continue
        return key.encode()

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

    print(f"Decrypted AES Key Length: {len(aes_key)} bytes")
    return aes_key, iv

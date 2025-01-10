# SuprSafe

**SuprSafe** is a simple and minimal file encryption software designed to keep your sensitive files secure using AES-256 encryption. With an easy-to-use command-line interface, SuprSafe ensures your files are encrypted and decrypted without the complexity.

## Features

- **AES-256 Encryption**: Industry-standard encryption for your files.
- **Secure File Deletion**: Original files are securely deleted after encryption or decryption to ensure no traces are left.
- **Minimal Interface**: Command-line based encryption and decryption, making it lightweight and straightforward.
- **Password Protection**: Secure encryption key storage with a password.

## Requirements

- Python 3.x
- Install required dependencies using `pip`:
  ```bash
  pip install cryptography
Installation
Clone or download the repository to your local machine.
Install dependencies:
bash
Copy code
pip install cryptography
Run the program:
bash
Copy code
python main.py
Usage
Once you run the program, you will be presented with a simple command-line interface to choose between encryption or decryption.

Encrypting Files
Run the program and choose the option to encrypt files.
Enter a main password that will be used to generate the AES key for encryption.
Select the files you want to encrypt.
Encrypted files will be saved with the .enc, .enc.tag, and .enc.nonce extensions.
Decrypting Files
Run the program and choose the option to decrypt files.
Enter the account password to unlock your encryption keys.
Enter the main password used for encryption.
Files will be decrypted and saved with their original file names.
Encrypted files will be securely deleted after decryption.
CLI Menu
text
Copy code
Welcome to SuprSafe!

Please choose an option:
1. Encrypt Files
2. Decrypt Files
3. Exit
Option 1: Encrypt Files
Option 2: Decrypt Files
Option 3: Exit
Security Considerations
Password Safety: Make sure you remember your main password, as it cannot be recovered if lost.
Secure Deletion: Encrypted files are securely deleted after encryption or decryption to avoid any traces of sensitive data.
License
SuprSafe is open-source and released under the MIT License.

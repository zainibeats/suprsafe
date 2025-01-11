# **SuprSafe**

**SuprSafe** is a powerful yet user-friendly file encryption software that safeguards your sensitive data using the industry-standard AES-256 algorithm. With its intuitive command-line interface (CLI), SuprSafe empowers you to encrypt and decrypt files effortlessly, ensuring their confidentiality without unnecessary complexity.

## Features

- **Robust AES-256 Encryption:** SuprSafe leverages the industry-leading AES-256 encryption standard to provide unparalleled security for your files.
- **Secure File Deletion:** Rest assured that after encryption or decryption, the original unencrypted files are meticulously deleted using secure methods, eliminating any traces of sensitive information.
- **Streamlined Interface:** The CLI-based approach fosters a lightweight and straightforward user experience, making SuprSafe easy to learn and use.
- **Password Protection:** SuprSafe safeguards your encryption keys with a user-defined password, ensuring an additional layer of security.

## Requirements

- **Python 3.x:** Ensure you have Python 3.x installed on your system.
- **Dependency Installation:** Install the necessary dependency using `pip`:

```bash
pip install cryptography
```

## Installation

1. **Clone or Download:** Obtain the SuprSafe codebase by cloning the repository or downloading it directly to your local machine.
2. **Install Dependencies:** Navigate to the SuprSafe directory in your terminal and execute the following command to install the required dependency:

```bash
pip install cryptography
```

## Running SuprSafe

1. **Start the Program:** Launch the software by running the following command in your terminal:

```bash
python main.py
```

## Usage

SuprSafe presents you with a user-friendly CLI menu upon execution. Here's how to interact with it:

**Encryption:**

1. **Choose Encryption:** Select option 1 ("Encrypt Files") from the menu.
2. **Set Password:** Define a robust password that will be used to generate the AES-256 encryption key. Choose a password you can remember well, as its loss will prevent access to your encrypted files.
3. **File Selection:** Specify the files you want to encrypt. SuprSafe allows you to select multiple files at once.
4. **Encrypted Files:** The encrypted files will be saved with extensions like `.enc`, `.enc.tag`, and `.enc.nonce` to indicate their encrypted state.

**Decryption:**

1. **Choose Decryption:** Select option 2 ("Decrypt Files") from the menu.
2. **Account Password:** Enter the password used to secure your encryption keys.
3. **Main Password:** Provide the main password you used during the encryption process.
4. **Decrypted Files:** The program will decrypt the selected files and restore them with their original filenames.
5. **Secure Deletion:** SuprSafe securely deletes the encrypted files after successful decryption, eliminating any potential data remnants.

## CLI Menu

```text
Welcome to SuprSafe!

Please choose an option:
  1. Encrypt Files
  2. Decrypt Files
  3. Exit
```

## Security Considerations

**Password Safety:**

- Exercise caution and select a strong and memorable main password. Losing this password will render your encrypted files inaccessible as there's no way to recover them. Consider using password management tools to store your password securely.

**Secure Deletion:**

- SuprSafe prioritizes security by using secure methods to eliminate the original files after encryption or decryption. This guarantees that no traces of sensitive data remain.

## License

SuprSafe is open-source software licensed under the permissive MIT License. This enables you to freely use, modify, and distribute SuprSafe while complying with the license terms (refer to the LICENSE file for details).

I hope this enhanced README.md provides a clear and informative guide for SuprSafe users!
# SuprSafe Main Key Generator

A secure key generation tool designed for use with SuprSafe encryption software. This tool generates cryptographically secure 32-character keys that are compatible with SuprSafe's encryption process.

![SuprSafe Main Key Generator](assets/images/suprsafe_mk_gen1.png)

## Features

- **Interactive Animations**: Visual feedback during key generation
- **Speed Control**: Hold Enter during animation to speed up the process
- **Memory Security**: Implements secure data wiping after key generation
- **Seeded Generation**: Option to create seeded keys from user input
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Reproducible Keys**: Generate the same key from the same seed input

## Installation

1. Clone the repository or download the release
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Quick Start

Run the program:

```bash
MainKeyGen.exe
```

## Usage Guide

### Basic Operation

1. **Start the Program**
   - Run using Python or the executable
   - You'll see a welcome message with options

2. **Generate a Random Key**
   - Simply press Enter or enter any text to create a seeded key
   - Watch the animation
   - Your 32-character key will be revealed

4. **Control Animation Speed**
   - Hold Enter during the animation to speed it up
   - Release to return to normal speed

5. **Exit the Program**
   - Type 'q', 'exit', or 'quit'
   - Press Enter

### Tips for Key Management

- **Save Your Key**: Write down or securely store the generated key
- **Key Format**: Keys are always 32 characters long
- **Verification**: Double-check your key when writing it down
- **Security**: Store the key (or seed) offline for maximum security

## Security Features

- Uses cryptographically secure random number generation
- Implements memory wiping for sensitive data
- No keys are stored in the program
- All generated keys are temporary and must be saved manually

## Reproducible Key Generation

- **Seeded Keys**: When you provide a seed (any text input), the generated key will be reproducible. This means using the same seed will always produce the same key.
- **Random Keys**: If no seed is provided, a random key is generated each time.

## Development

Project structure:

```
src/mk_gen/
├── assets/           # Static assets
├── src/             # Source code
│   ├── animations/  # Animation classes
│   │   ├── base.py    # Base animation class
│   │   ├── key_gen.py # Key generation animation
│   │   └── party.py   # Party mode animation
│   ├── utils/      # Utility functions
│   │   ├── audio.py   # Audio playback
│   │   └── security.py # Security functions
│   └── main_key.py # Main entry point
├── requirements.txt # Dependencies
└── main_key.spec   # PyInstaller spec
```

## Building from Source

To create an executable:

```bash
pyinstaller main_key.spec
```

The executable will be created in the `dist` directory.

## Integration with SuprSafe

This tool is designed to work with SuprSafe encryption software. For full documentation on using SuprSafe, please refer to the main SuprSafe README.

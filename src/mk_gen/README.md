# SuprSafe Main Key Generator

A secure key generation tool to be used with SuprSafe.

## Installation

1. Clone the repository
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the program:

```bash
python src/main_key.py
```

Or build the executable:

```bash
pyinstaller main_key.spec
```

## Features

- Secure key generation using cryptographically secure random numbers
- Seeded key generation from user input for reproducible keys
- Interactive animations with speed control (Hold enter to speed up)
- Memory-secure operations with secure data wiping
- Colorful terminal interface
- Fully open source

## Development

Project structure:

```
src/mk_gen/
├── assets/           # Static assets (audio)
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

## Security

- Uses Python's `secrets` module for cryptographically secure random generation
- Implements secure memory wiping for sensitive data
- Cross-platform secure input handling
- No hardcoded sensitive information

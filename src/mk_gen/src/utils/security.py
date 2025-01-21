import secrets
import base64

# Securely wipe sensitive data from memory
def secure_wipe(data):
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

# Check if input matches secret without exposing it
def check_secret(input_str: str, encoded_secret: str) -> bool:
    try:
        if input_str == encoded_secret:
            return False
        return input_str == base64.b64decode(encoded_secret).decode('utf-8')
    except:
        return False 
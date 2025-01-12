import secrets
import base64

# Function to generate key
def generate_aes_key():
    key = secrets.token_bytes(24)  # 24 bytes will encode to 32 base64 chars
    key_str = base64.b64encode(key).decode('utf-8')
    assert len(key_str) == 32, "Key string must be 32 characters"
    return key, key_str

# Main function
def main():
    def supports_color():
        import sys
        import os
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty() and \
               ('ANSICON' in os.environ or 'WT_SESSION' in os.environ or \
                os.environ.get('TERM', '').lower() != 'dumb')

    # Use normal string if colors aren't supported
    warning_text = "\033[91m(DO NOT LOSE THIS)\033[0m" if supports_color() else "(DO NOT LOSE THIS)"
    
    while True:
        # Generate a key
        key_bytes, key_str = generate_aes_key()
        
        try:
            # Print the key
            print(f"Main Key {warning_text}: \n{key_str}")
            
            # Prompt for regenerate or quit
            choice = input("\nPress Enter to regenerate a new key or type 'exit' or 'q' to quit: \n").lower()
            
            # Check if the user wants to exit
            if choice in ['q', 'quit', 'exit']:
                break
        finally:
            # Clear sensitive data from memory
            key_bytes = secrets.token_bytes(len(key_bytes))  # Overwrite with random data
            key_str = None
            
# Run the main function
if __name__ == "__main__":
    main()

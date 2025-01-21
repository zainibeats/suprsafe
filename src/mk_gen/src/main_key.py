import secrets
import base64
from colorama import init, Fore, Style
import time
import random
import hashlib
import gc

# Local imports
from animations.key_gen import KeyGenAnimation
from animations.party import PartyAnimation
from utils.audio import play_secret_audio
from utils.security import secure_wipe, check_secret

# Initialize colorama
init(autoreset=True)

# Encoded secret
_ENCODED_SECRET = "dGlyZWQgZXllcw=="

def create_seed_from_input(user_input: str) -> int:
    """Create a unique seed from user input."""
    hasher = hashlib.sha256()
    hasher.update(user_input.encode())
    time_bytes = str(time.time()).encode()
    hasher.update(time_bytes)
    return int.from_bytes(hasher.digest()[:8], 'big')

def generate_aes_key(user_input: str | None = None) -> tuple[bytes, str]:
    """Generate an AES key, optionally using user input as seed."""
    if user_input:
        seed = create_seed_from_input(user_input)
        random.seed(seed)
        
        mixed_bytes = bytearray()
        for _ in range(24):
            sys_byte = secrets.randbelow(256)
            seeded_byte = random.randint(0, 255)
            mixed_byte = (sys_byte + seeded_byte) % 256
            mixed_bytes.append(mixed_byte)
        
        key = bytes(mixed_bytes)
    else:
        key = secrets.token_bytes(24)
    
    key_str = base64.b64encode(key).decode('utf-8')
    assert len(key_str) == 32, "Key string must be 32 characters"
    return key, key_str

def reveal_final_key(key_str: str, animation: KeyGenAnimation) -> None:
    # Clear the line
    print('\r' + ' ' * 100, end='\r', flush=True)
    
    # Show static "Main Key" text
    print(f"Main Key {Fore.RED}(DO NOT LOSE THIS){Style.RESET_ALL}: ", end='', flush=True)
    
    # Reveal the key character by character with speed based on animation state
    delay = 0.005 if animation.is_sped_up() else 0.02
    for i in range(len(key_str)):
        print(key_str[i], end='', flush=True)
        time.sleep(delay)
    print()  # New line at the end

def main() -> None:
    """Main program entry point."""
    print(f"{Fore.CYAN}Press Enter to generate a random key")
    print(f"Or type anything to use it as a seed for key generation")
    print(f"Type 'exit' or 'q' to quit")
    
    party_anim = PartyAnimation()
    
    while True:
        choice = input().lower()
        
        if choice in ['q', 'quit', 'exit']:
            break
            
        if check_secret(choice, _ENCODED_SECRET):
            play_secret_audio()
            party_anim.start()
            
            # Run for shorter duration if sped up
            start_time = time.time()
            duration = 10  # Normal duration
            while time.time() - start_time < duration:
                if party_anim.is_sped_up():
                    # Exit early if sped up
                    break
                time.sleep(0.1)
            
            party_anim.stop()
            print(f"\n{Fore.CYAN}Press Enter for new key, type for seeded key, or 'q' to quit{Style.RESET_ALL}")
            continue
        
        # Normal key generation
        key_anim = KeyGenAnimation()
        key_anim.start()
        
        try:
            time.sleep(0.5)
            key_bytes, key_str = generate_aes_key(choice if choice else None)
            key_anim.stop()
            reveal_final_key(key_str, key_anim)
            print(f"\n{Fore.CYAN}Press Enter for new key, type for seeded key, or 'q' to quit{Style.RESET_ALL}")
            
        finally:
            # Clean up
            if key_anim._thread and key_anim._thread.is_alive():
                key_anim.stop()
            
            # Secure cleanup of sensitive data
            if choice:
                choice = secure_wipe(choice)
            if 'key_bytes' in locals():
                key_bytes = secure_wipe(key_bytes)
            if 'key_str' in locals():
                key_str = secure_wipe(key_str)
            
            gc.collect()

if __name__ == "__main__":
    main() 
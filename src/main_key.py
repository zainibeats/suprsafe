import secrets
import base64
from colorama import init, Fore, Style
import time
import random
import sys
import threading

init()  # Initialize colorama

# Global animation flag
_stop_animation = False

def animate_key_generation(final_key_str, message="Generating secure key"):
    global _stop_animation
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    # First phase: random animation
    while not _stop_animation:
        random_str = ''.join(random.choice(chars) for _ in range(32))
        print(f"\r{Fore.CYAN}{message}: {Fore.GREEN}{random_str}{Style.RESET_ALL}", end='', flush=True)
        time.sleep(0.1)

def reveal_final_key(final_key_str):
    # Clear the line
    print('\r' + ' ' * 100, end='\r', flush=True)
    
    # Show static "Main Key" text
    print(f"Main Key {Fore.RED}(DO NOT LOSE THIS){Style.RESET_ALL}: ", end='', flush=True)
    
    # Reveal the key character by character
    for i in range(len(final_key_str)):
        print(final_key_str[i], end='', flush=True)
        time.sleep(0.02)
    print()  # New line at the end

def start_key_animation(message="Generating secure key"):
    global _stop_animation
    _stop_animation = False
    animation_thread = threading.Thread(target=lambda: animate_key_generation(message))
    animation_thread.daemon = True
    animation_thread.start()
    return animation_thread

def stop_key_animation(thread):
    global _stop_animation
    _stop_animation = True
    thread.join(timeout=1)

def generate_aes_key():
    key = secrets.token_bytes(24)  # 24 bytes will encode to 32 base64 chars
    key_str = base64.b64encode(key).decode('utf-8')
    assert len(key_str) == 32, "Key string must be 32 characters"
    return key, key_str

def main():
    print(f"{Fore.CYAN}Press Enter to generate a key, or type 'exit' or 'q' to quit.{Style.RESET_ALL}")
    
    while True:
        choice = input().lower()
        
        if choice in ['q', 'quit', 'exit']:
            break
            
        # Start animation
        animation_thread = start_key_animation()
        
        try:
            # Generate key (adding small delay for animation effect)
            time.sleep(0.5)  # Let animation run briefly
            key_bytes, key_str = generate_aes_key()
            
            # Stop animation
            stop_key_animation(animation_thread)
            
            # Reveal the final key with typing effect
            reveal_final_key(key_str)
            
            print(f"\n{Fore.CYAN}Press Enter to generate another key, or type 'exit' or 'q' to quit.{Style.RESET_ALL}")
            
        finally:
            # Clean up
            if animation_thread.is_alive():
                stop_key_animation(animation_thread)
            # Clear sensitive data from memory
            key_bytes = secrets.token_bytes(len(key_bytes))
            key_str = None

if __name__ == "__main__":
    main()

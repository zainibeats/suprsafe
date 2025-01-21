from colorama import Fore, Style
import random
import time
from .base import BaseAnimation

# Key generation animation class
class KeyGenAnimation(BaseAnimation):
    def __init__(self, message: str = "Generating secure key") -> None:
        super().__init__()
        self.message = message
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    def _animation_loop(self) -> None:
        frames = 0
        delay = 0.1
        start_time = time.time()
        duration = 2  # Normal duration in seconds
        
        while self._running and (time.time() - start_time < (0.5 if self._speed_up else duration)):
            random_str = ''.join(random.choice(self.chars) for _ in range(32))
            print(f"\r{Fore.CYAN}{self.message}: {Fore.GREEN}{random_str}{Style.RESET_ALL}", end='', flush=True)
            
            if self._check_enter():
                delay = 0.02  # Speed up animation rate
            
            time.sleep(delay)
            frames += 1 
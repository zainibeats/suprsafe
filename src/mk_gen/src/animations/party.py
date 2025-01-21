from colorama import Fore, Style
import random
from typing import List
import time
from .base import BaseAnimation

# Party animation class
class PartyAnimation(BaseAnimation):
    def __init__(self) -> None:
        super().__init__()
        self.colors: List[str] = [Fore.GREEN, Fore.CYAN, Fore.YELLOW, Fore.MAGENTA, Fore.BLUE, Fore.RED]
    
    # Party animation loop
    def _animation_loop(self) -> None:
        frames = 0
        base_text = "suprsafesuprsafe"
        start_time = time.time()
        delay = 0.1
        duration = 10  # Normal duration in seconds
        
        while self._running and (time.time() - start_time < (1 if self._speed_up else duration)):
            wave_pos = frames % len(base_text)
            party_text = ''.join(
                char.upper() if abs((i - wave_pos) % len(base_text)) < 3 else char.lower()
                for i, char in enumerate(base_text * 3)
            )
            
            # Full rainbow effect for the entire line
            colored_text = f"{random.choice(self.colors)}Generating secure key: " + \
                         ''.join(f"{random.choice(self.colors)}{char}" for char in party_text)
            
            print(f"\r{colored_text}{Style.RESET_ALL}", end='', flush=True)
            
            if self._check_enter():
                delay = 0.02  # Speed up animation rate
            
            time.sleep(delay)
            frames += 1 
import threading
import sys
import os
from abc import ABC, abstractmethod

# Import OS-specific keyboard input handlers
if os.name == 'nt':
    import msvcrt
else:
    import select

class BaseAnimation(ABC):
    def __init__(self) -> None:
        # Core animation state
        self._running: bool = True
        self._thread: threading.Thread | None = None
        self._speed_up: bool = False
        self._stop_requested = False
    
    def start(self) -> None:
        # Start animation in daemon thread to prevent blocking on program exit
        self._running = True
        self._speed_up = False
        self._stop_requested = False
        self._thread = threading.Thread(target=self._animation_loop)
        self._thread.daemon = True
        self._thread.start()
    
    # Stop the animation
    def stop(self) -> None:
        # Request immediate stop
        self._stop_requested = True
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
            print('\r' + ' ' * 100, end='\r', flush=True)  # Clear line
    
    def is_sped_up(self) -> bool:
        # Check if animation is in speed-up mode
        return self._speed_up
    
    def _check_enter(self) -> bool:
        # Cross-platform Enter key detection without blocking
        if os.name == 'nt':
            if not msvcrt.kbhit():
                return False
            # Clear input buffer by reading all pending input
            while msvcrt.kbhit():
                key = msvcrt.getch()
                if key in [b'\r', b'\n']:
                    self._speed_up = True  # Set speed-up state when Enter is pressed
                    return True
            return False
        else:  # Unix-like systems
            rlist, _, _ = select.select([sys.stdin], [], [], 0)
            if not rlist:
                return False
            # Clear input buffer
            char = sys.stdin.read(1)
            while select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.read(1)
            if char in ['\r', '\n']:
                self._speed_up = True  # Set speed-up state when Enter is pressed
                return True
            return False
    
    @abstractmethod
    def _animation_loop(self) -> None:
        # Abstract method: Child classes must implement their own animation logic
        pass 
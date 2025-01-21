import os
import sys

# Play the secret audio file
def play_secret_audio():
    # Get the base path - handle both PyInstaller and normal Python
    if getattr(sys, 'frozen', False):
        # Running in a PyInstaller bundle
        base_path = sys._MEIPASS  # type: ignore # PyInstaller-specific attribute
    else:
        # Running in normal Python environment
        base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
    
    audio_path = os.path.join(base_path, 'assets', 'audio', 'te.wav')
    
    if os.path.exists(audio_path):
        if os.name == 'nt':
            import winsound
            winsound.PlaySound(audio_path, winsound.SND_FILENAME | winsound.SND_ASYNC)
        else:
            import subprocess
            subprocess.Popen(['aplay', audio_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        print(f"Audio file not found at: {audio_path}", file=sys.stderr) 
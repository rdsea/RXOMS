import os
from pathlib import Path

try:
    RXOMS_PATH = os.getenv("RXOMS_PATH")
except KeyError:
    print("RXOMS_PATH not sent. Defaulting to ~/.odop")
    RXOMS_PATH = None

if RXOMS_PATH is None:
    user_home = Path.home()
    # assume that we have odop dir
    RXOMS_PATH = os.path.join(user_home, ".odop")
    os.makedirs(RXOMS_PATH, exist_ok=True)

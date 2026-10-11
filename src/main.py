#!/usr/bin/env python3
"""
FileRecover Pro – Windows Desktop File Recovery Prototype
Entry point.
"""

import sys
from pathlib import Path

# Ensure the src directory is on the path when running as script
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import customtkinter as ctk
except ImportError:
    print("Missing dependency: customtkinter")
    print("Install with:  pip install -r requirements.txt")
    sys.exit(1)

from ui.main_window import MainWindow


def main() -> None:
    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    main()

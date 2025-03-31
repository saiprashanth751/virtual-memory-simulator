# src/main.py
import sys
from pathlib import Path
from gui import start_gui

def setup_environment():
    """Create required directories and files"""
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    
    addresses = data_dir / "addresses.txt"
    if not addresses.exists():
        addresses.write_text("\n".join(["1", "2", "3", "4", "1", "2", "5"]))
    

    backing_store = data_dir / "BACKING_STORE.bin"
    if not backing_store.exists():
        backing_store.write_bytes(b'\0' * 65536)  # 256 pages × 256 bytes

if __name__ == "__main__":
    try:
        setup_environment()
        start_gui()
    except Exception as e:
        print(f"Critical error: {str(e)}")
        sys.exit(1)
import sys

# Centralized logging for consistent console output formatting (or future log file writes).
def info(message):
    print(f"[INFO] {message}")

def success(message):
    print(f"[+] {message}")

def warning(message):
    print(f"[!] {message}")

def error(message):
    print(f"[ERROR] {message}", file=sys.stderr)

def logtext(message):
    print(message)

def pretty(message):
    # Use ASCII-compatible check mark or fallback for environments without UTF-8
    try:
        print(f"[✔] {message}")
    except UnicodeEncodeError:
        print(f"[OK] {message}")
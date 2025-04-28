# Centralized logging for consistent console output formatting (or future log file writes).
def info(message):
    print(f"[+] {message}")

def warning(message):
    print(f"[!] {message}")

def error(message):
    print(f"[X] {message}")

def logtext(message):
    print(f"[*] {message}")

import re
from utils import file_utils, logger

### Scans extracted strings and decompiled source files for sensitive patterns: API keys, tokens, passwords, etc.

def scan_for_secrets(file_path):
    logger.info(f"[+] Scanning {file_path} for secrets...")

    if not file_utils.file_exists(file_path):
        logger.warning(f"File {file_path} not found. Skipping secrets scan.")
        return
    
    content = file_utils.read_file(file_path)

    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "Bearer Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        "Hardcoded Password": r"password\s*=\s*[\"'][^\"']+[\"']",
        "Private Key": r"-----BEGIN PRIVATE KEY-----"
    }

    for name, regex in patterns.items():
        matches = re.findall(regex, content)
        if matches:
            logger.warning(f"[*] {name} found: {len(matches)} occurrence(s)")
            for match in matches:
                print(f"    {match}")

if __name__ == "__main__":
    import sys
    scan_for_secrets(sys.argv[1])

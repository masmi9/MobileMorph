import subprocess
import frida
from utils import logger

def get_local_frida_version():
    """Get Frida client version installed on local machine."""
    try:
        output = subprocess.check_output(["frida", "--version"], text=True)
        return output.strip()
    except Exception as e:
        logger.error(f"[!] Error checking local Frida version: {e}")
        return None

def get_remote_frida_version():
    """Get Frida server version running on connected Android device."""
    try:
        device = frida.get_usb_device(timeout=5)
        version = device.get_frida_version()
        return version
    except Exception as e:
        logger.error(f"[!] Error checking remote Frida version: {e}")
        return None

def check_frida_version_match():
    """Compares local and remote Frida versions."""
    local_version = get_local_frida_version()
    remote_version = get_remote_frida_version()

    if not local_version or not remote_version:
        logger.warning("[!] Could not retrieve Frida versions for comparison.")
        return False

    if local_version == remote_version:
        logger.info(f"[+] Frida client and server versions match: {local_version}")
        return True
    else:
        logger.error(f"[X] Frida version mismatch! Local: {local_version} | Remote: {remote_version}")
        logger.error("[-] Please download matching frida-server for your client version from https://github.com/frida/frida/releases")
        return False

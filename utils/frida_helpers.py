import subprocess
import frida
from utils import logger

def get_local_frida_version():
    """Get Frida client version installed on local machine."""
    try:
        output = subprocess.check_output(["frida", "--version"], text=True)
        return output.strip()
    except Exception as e:
        logger.error(f"Error checking local Frida version: {e}")
        return None

def get_remote_frida_version():
    """Get Frida server version running on connected Android device."""
    try:
        device = frida.get_usb_device(timeout=5)
        version = device.get_frida_version()
        return version
    except Exception as e:
        logger.error(f"Error checking remote Frida version: {e}")
        return None

def check_frida_version_match():
    try:
        # Check local frida version (your Windows machine)
        local_version = subprocess.check_output(["frida", "--version"], text=True).strip()
        logger.info(f"Local Frida version: {local_version}")
    except Exception as e:
        logger.error(f"Error checking local Frida version: {e}")
        logger.warning("Proceeding without local Frida version check.")
        return True  # Allow it to continue even if local version missing

    try:
        # Check remote frida-server version
        device = frida.get_usb_device()
        remote_version = device.query_system_parameters().get('frida.version', None)
        if remote_version:
            logger.info(f"Remote Frida server version: {remote_version}")
        else:
            logger.warning("Could not retrieve remote Frida server version.")
    except Exception as e:
        logger.error(f"Error checking remote Frida version: {e}")
        logger.warning("Proceeding without remote Frida version check.")
        return True  # Allow it to continue even if remote version missing

    # Optional strict matching (you can remove this block if not needed)
    if local_version and remote_version and local_version.split(".")[0] != remote_version.split(".")[0]:
        logger.error("Frida major versions mismatch! Unexpected behavior possible.")
        return False

    return True

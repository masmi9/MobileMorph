import subprocess

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    from utils import logger
    logger.error("Frida module is not installed. Dynamic analysis will fail.")
    FRIDA_AVAILABLE = False

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
    if not FRIDA_AVAILABLE:
        logger.warning("Frida module not available, cannot check remote version.")
        return None

    try:
        device = frida.get_usb_device(timeout=5)
        version = device.get_frida_version()
        return version
    except Exception as e:
        logger.error(f"Error checking remote Frida version: {e}")
        return None

def check_frida_version_match():
    """Compare local Frida version with remote frida-server version."""
    local_version = get_local_frida_version()
    if local_version:
        logger.info(f"Local Frida version: {local_version}")
    else:
        logger.warning("Local Frida version check failed.")
        return True  # Let pipeline proceed

    if not FRIDA_AVAILABLE:
        logger.warning("Frida module missing. Skipping remote version check.")
        return True

    remote_version = get_remote_frida_version()
    if remote_version:
        logger.info(f"Remote Frida server version: {remote_version}")
    else:
        logger.warning("Remote Frida version check failed.")
        return True  # Let pipeline proceed

    # Optional strict major version match
    if local_version and remote_version:
        if local_version.split(".")[0] != remote_version.split(".")[0]:
            logger.error("Frida major versions mismatch! Unexpected behavior possible.")
            return False

    return True

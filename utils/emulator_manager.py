import subprocess
import os
import time
import urllib.request
import lzma
import shutil
from utils import logger

AVD_NAME = "mobilemorph_emulator"
SNAPSHOT_NAME = "frida_ready"
SYSTEM_IMAGE = "system-images;android-30;google_apis;x86"
FRIDA_VERSION = "16.1.6"
ARCH = "x86"  # Use "arm64" if you're setting up a real device
TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")
FRIDA_BINARY = os.path.join(TOOLS_DIR, "frida-server")

def download_frida_server():
    logger.logtext("frida-server not found. Downloading...")

    platform = "android-x86" if ARCH == "x86" else "android-arm64"
    url = f"https://github.com/frida/frida/releases/download/{FRIDA_VERSION}/frida-server-{FRIDA_VERSION}-{platform}.xz"
    dest_xz = FRIDA_BINARY + ".xz"

    os.makedirs(TOOLS_DIR, exist_ok=True)

    logger.logtext(f"Downloading {url}...")
    urllib.request.urlretrieve(url, dest_xz)
    logger.logtext("Extracting...")
    with lzma.open(dest_xz) as f_in, open(FRIDA_BINARY, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.chmod(FRIDA_BINARY, 0o755)
    os.remove(dest_xz)
    logger.pretty(f"frida-server downloaded and ready at: {FRIDA_BINARY}")

def ensure_emulator_ready():
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk_root:
        raise EnvironmentError("ANDROID_HOME or ANDROID_SDK_ROOT must be set.")

    avdmanager = os.path.join(sdk_root, "cmdline-tools/latest/bin/avdmanager")
    emulator = os.path.join(sdk_root, "emulator/emulator")
    sdkmanager = os.path.join(sdk_root, "cmdline-tools/latest/bin/sdkmanager")

    # 1. Install system image
    subprocess.run(f'yes | {sdkmanager} "{SYSTEM_IMAGE}"', shell=True, check=True)

    # 2. Create AVD if needed
    avd_list = subprocess.check_output(f'{avdmanager} list avd', shell=True, text=True)
    if AVD_NAME not in avd_list:
        subprocess.run(f'echo no | {avdmanager} create avd -n {AVD_NAME} -k "{SYSTEM_IMAGE}" --force', shell=True, check=True)

    # 3. Launch emulator with snapshot save trigger
    subprocess.Popen(
        [emulator, "-avd", AVD_NAME, "-no-window", "-no-audio", "-writable-system", "-selinux", "permissive"]
    )

    # 4. Wait for full boot
    logger.logtext("Waiting for emulator to boot...")
    subprocess.run(["adb", "wait-for-device"], check=True)
    while True:
        result = subprocess.run(["adb", "shell", "getprop", "sys.boot_completed"], capture_output=True, text=True)
        if result.stdout.strip() == "1":
            break
        time.sleep(2)
    logger.info("Emulator booted.")

    # 5. Gain root access and remount system
    logger.logtext("Gaining root access...")
    subprocess.run(["adb", "root"], check=True)
    time.sleep(2)
    logger.logtext("Remounting /system as read-write...")
    subprocess.run(["adb", "remount"], check=True)

    # 6. Download frida-server if needed
    if not os.path.isfile(FRIDA_BINARY):
        download_frida_server()

    # 7. Push frida-server
    logger.logtext("Pushing frida-server...")
    subprocess.run(["adb", "push", FRIDA_BINARY, "/data/local/tmp/"], check=True)
    subprocess.run(["adb", "shell", "chmod", "755", "/data/local/tmp/frida-server"], check=True)
    subprocess.run(["adb", "shell", "/data/local/tmp/frida-server", "&"], shell=True)

    # 7. Save emulator snapshot
    logger.logtext("Saving emulator snapshot...")
    subprocess.run(["adb", "emu", "avd", "snapshot", "save", SNAPSHOT_NAME], check=True)
    logger.pretty(f"Emulator ready and snapshot '{SNAPSHOT_NAME}' saved.")

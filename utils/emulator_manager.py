import subprocess
import os
import time
import lzma
import shutil
import requests
import platform
from utils import logger

AVD_NAME = "mobilemorph_emulator"
SNAPSHOT_NAME = "frida_ready"
FRIDA_VERSION = "16.1.6"
TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")
FRIDA_BINARY = os.path.join(TOOLS_DIR, "frida-server")

def get_apk_native_code(apk_path):
    try:
        output = subprocess.check_output(["aapt", "dump", "badging", apk_path], text=True)
        for line in output.splitlines():
            if line.startswith("native-code"):
                codes = line.split(":")[1].strip().strip("'").split("' '")
                return codes
    except subprocess.CalledProcessError:
        pass
    return []

def download_frida_server():
    global ARCH
    logger.logtext("frida-server not found. Downloading...")

    platform = "android-x86" if ARCH == "x86" else "android-arm64"
    url = f"https://github.com/frida/frida/releases/download/{FRIDA_VERSION}/frida-server-{FRIDA_VERSION}-{platform}.xz"
    dest_xz = FRIDA_BINARY + ".xz"

    os.makedirs(TOOLS_DIR, exist_ok=True)

    logger.logtext(f"Downloading {url}...")
    response = requests.get(url, stream=True)
    with open(dest_xz, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    
    logger.logtext("Extracting...")
    with lzma.open(dest_xz) as f_in, open(FRIDA_BINARY, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.chmod(FRIDA_BINARY, 0o755)
    os.remove(dest_xz)
    logger.pretty(f"frida-server downloaded and ready at: {FRIDA_BINARY}")

def ensure_emulator_ready(apk_path):
    native_arch = get_apk_native_code(apk_path)
    logger.logtext(f"Detected APK architectures: {native_arch}")
    # Pick system image and architecture based on APK native-code
    global SYSTEM_IMAGE
    global ARCH

    if 'x86_64' in native_arch or 'x86' in native_arch:
        logger.logtext("APK supports x86/x86_64")
        SYSTEM_IMAGE = "system-images;android-27;google_apis;x86"
        ARCH = "x86"
    elif 'arm64-v8a' in native_arch:
        logger.logtext("APK requires ARM64 architecture.")
        if platform.system() == "Windows":
            logger.warning("Forcing x86 system image because Windows host can't run arm64 emulators.")
            SYSTEM_IMAGE = "system-images;android-30;google_apis;x86"
        else:
            SYSTEM_IMAGE = "system-images;android-29;google_apis;arm64-v8a"
            ARCH = "arm64"
    else:
        logger.warning("Could not determine APK architecture. Defaulting to x86.")
        SYSTEM_IMAGE = "system-images;android-30;google_apis;x86"
        ARCH = "x86"

    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk_root:
        raise EnvironmentError("ANDROID_HOME or ANDROID_SDK_ROOT must be set.")

    sdkmanager = os.path.join(sdk_root, "cmdline-tools", "latest", "bin", "sdkmanager.bat")
    avdmanager = os.path.join(sdk_root, "cmdline-tools", "latest", "bin", "avdmanager.bat")
    emulator = os.path.join(sdk_root, "emulator", "emulator.exe")

    # 1. Install system image
    subprocess.run([sdkmanager ,SYSTEM_IMAGE], check=True)
    logger.warning("If prompted, accept licenses in the terminal.")

    # 2. Create AVD if needed
    avd_list = subprocess.check_output(f'{avdmanager} list avd', shell=True, text=True)
    if AVD_NAME not in avd_list:
        subprocess.run(f'echo no | {avdmanager} create avd -n {AVD_NAME} -k "{SYSTEM_IMAGE}" --force', shell=True, check=True)

    # 3. Launch emulator with snapshot save trigger
    logger.logtext("Starting emulator with snapshot (if available)...")
    subprocess.Popen(
        [emulator, "-avd", AVD_NAME, "-no-window", "-no-audio", "-writable-system", "-selinux", "permissive", "-snapshot", SNAPSHOT_NAME]
    )

    # 4. Wait for full boot
    logger.logtext("Waiting for emulator to boot...")
    subprocess.run(["adb", "wait-for-device"], check=True)
    start_time =time.time()
    while True:
        result = subprocess.run(["adb", "shell", "getprop", "sys.boot_completed"], capture_output=True, text=True)
        if result.stdout.strip() == "1":
            break
        if time.time() - start_time > 60:
            raise TimeoutError("Device did not boot within 60 seconds.")
        time.sleep(2)
    logger.info("Emulator booted.")

    # 5. Gain root access and remount system
    logger.logtext("Gaining root access...")
    subprocess.run(["adb", "root"], check=True)
    time.sleep(2)

    try:
        logger.logtext("Remounting /system as read-write (will skip if slow)...")
        subprocess.run(["adb", "remount"], check=True, timeout=10)
    except subprocess.TimeoutExpired:
        logger.warning("Remount timed out. Continue without remount.")

    # 6. Download frida-server if needed
    if not os.path.isfile(FRIDA_BINARY):
        download_frida_server()

    # 7. Check if frida-server is already on the device. If not, push frida-server
    result = subprocess.run(["adb", "shell", "ls", "/data/local/tmp/frida-server"], capture_output=True, text=True)
    if "No such file" in result.stdout:
        logger.logtext("Pushing frida-server...")
        subprocess.run(["adb", "push", FRIDA_BINARY, "/data/local/tmp/"], check=True)
        subprocess.run(["adb", "shell", "chmod", "755", "/data/local/tmp/frida-server"], check=True)
        subprocess.run(["adb", "shell", "/data/local/tmp/frida-server", "&"], shell=True)
    else:
        logger.logtext("frida-server already on device.")

    # 8. Save emulator snapshot for future fast boots
    logger.logtext("Saving emulator snapshot...")
    subprocess.run(["adb", "emu", "avd", "snapshot", "save", SNAPSHOT_NAME], check=True)
    logger.pretty(f"Emulator ready and snapshot '{SNAPSHOT_NAME}' saved.")

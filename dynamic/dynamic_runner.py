import time
import threading
import subprocess
from dynamic.traffic_interceptor import FridaTrafficInterceptor
from utils import logger

def check_device_connection():
    result = subprocess.check_output("adb devices", shell=True, text=True)
    devices = [line for line in result.splitlines() if "\tdevice" in line]
    if not devices:
        logger.error("No devices/emulators connected. Please connect a device and try again.")
        return False
    return True

def get_package_name_from_apk(apk_path):
    """Extracts the package name from APK using aapt."""
    try:
        output = subprocess.check_output(["aapt", "dump", "badging", apk_path], shell=True, text=True)
        for line in output.splitlines():
            if line.startswith("package:"):
                parts = line.split()
                for part in parts:
                    if part.startswith("name="):
                        return part.split("=")[1].replace("'", "")
    except subprocess.CalledProcessError as e:
        logger.error(f"[X] Failed to extract package name: {e}")
    return None

def uninstall_app(package_name):
    """Uninstalls the app if it's already installed."""
    logger.info(f"[*] Uninstalling existing app {package_name} (if present)...")
    subprocess.run(["adb", "uninstall", package_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_for_process(package_name, timeout=10):
    """Waits for the app process to start."""
    logger.info(f"[*] Waiting for process {package_name} to start...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        result = subprocess.run(["adb", "shell", "pidof", package_name], capture_output=True, text=True)
        if result.stdout.strip():
            logger.info(f"[+] Process {package_name} is running.")
            return True
        time.sleep(1)
    logger.error(f"[X] Timeout: {package_name} process not found.")
    return False

def run_frida_script(script_path, package_name):
    print(f"[*] Running Frida script: {script_path}")
    subprocess.run([
        "frida", "-U", "-n", package_name, "-l", script_path, "--no-pause"
    ])

def start_dynamic_analysis(app_path):
    """Launch dynamic analysis and start traffic interception."""
    logger.info(f"Starting dynamic analysis for {app_path}...")

    if not check_device_connection():
        return

    if app_path.endswith(".apk"):
        package_name = get_package_name_from_apk(app_path)
        if not package_name:
            logger.error("Failed to extract package name - aborting dynamic analysis.")
            return
        
        uninstall_app(package_name)

        logger.info(f"[*] Installing {app_path}...")
        subprocess.run(["adb", "install", app_path])

        logger.info(f"[*] Launching app {package_name}")
        subprocess.run(["adb", "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"])
        
        if not wait_for_process(package_name):
            return

    else:
        logger.error("Unsupported app format. Only APK supported.")
        return

    logger.info(f"Package name: {package_name}")

    interceptor = FridaTrafficInterceptor(package_name)
    interceptor.start_hook()

    frida_scripts = [
        "dynamic/frida_hooks/bypass_ssl.js",
        "dynamic/frida_hooks/hook_crypt.js",
        "dynamic/frida_hooks/network_logger.js"
    ]

    threads = []
    for script in frida_scripts:
        t = threading.Thread(target=run_frida_script, args=(script, package_name))
        t.start()
        threads.append(t)

    logger.info("[*] Frida hooks running. You can interact with the app now.")
    time.sleep(30)

    for t in threads:
        t.join()

    logger.info("Dynamic analysis finished successfully!")

# NEW: The class wrapper for dynamic analysis

class DynamicAnalysisEngine:
    def __init__(self, app_path):
        self.app_path = app_path

    def start(self):
        start_dynamic_analysis(self.app_path)

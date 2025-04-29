import os
import sys
import time
import threading
import subprocess
from dynamic.traffic_interceptor import FridaTrafficInterceptor
from dynamic.traffic_interceptor_ios import FridaTrafficInterceptorIOS
from utils import logger, frida_helpers

def check_device_connection():
    result = subprocess.check_output("adb devices", shell=True, text=True)
    devices = [line for line in result.splitlines() if "\tdevice" in line]
    if not devices:
        logger.error("No devices/emulators connected. Please connect a device and try again.")
        return False
    return True

def ensure_frida_server_running():
    """Ensure frida-server is running on the connected device."""
    try:
        logger.info("Checking if frida-server is already running...")
        result = subprocess.run(
            ["adb", "shell", "ps | grep frida-server | grep -v grep"],
            shell=True, capture_output=True, text=True
        )

        if "frida-server" in result.stdout:
            logger.info("Frida-server already running.")
            return

        logger.warning("Frida-server not running. Attempting to start it...")

        # Push frida-server binary if not already pushed
        local_frida_path = "tools/frida-server"  # Adjust path where you store frida-server
        remote_frida_path = "/data/local/tmp/frida-server"

        logger.info("Pushing frida-server to device...")
        subprocess.run(["adb", "push", local_frida_path, remote_frida_path], check=True)

        # Set executable permissions
        logger.info("Setting executable permissions...")
        subprocess.run(["adb", "shell", "chmod", "755", remote_frida_path], check=True)

        # Start frida-server in background
        logger.info("Starting frida-server...")
        subprocess.run(["adb", "shell", remote_frida_path, "&"], shell=True)

        logger.info("Frida-server started successfully.")
        
        # Give it a moment to boot
        time.sleep(5)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start frida-server: {e}")
        sys.exit(1)

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
        logger.error(f"Failed to extract package name: {e}")
    return None

def get_main_activity(apk_path):
    """Extracts the main activity from APK using aapt."""
    try:
        output = subprocess.check_output(["aapt", "dump", "badging", apk_path], shell=True, text=True)
        for line in output.splitlines():
            if line.startswith("launchable-activity:"):
                parts = line.split()
                for part in parts:
                    if part.startwith("name="):
                        return part.split("=")[1].replace("'", "")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to extract main activity: {e}")
    return None

def uninstall_app(package_name):
    """Uninstalls the app if it's already installed."""
    logger.info(f"Uninstalling existing app {package_name} (if present)...")
    subprocess.run(["adb", "uninstall", package_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def launch_app(package_name, main_activity):
    logger.info(f"Launching {package_name}/{main_activity}...")
    try:
        subprocess.run([
            "adb", "shell", "am", "start",
            "-n", f"{package_name}/{main_activity}"
        ], check=True)
        logger.info("App launched successfully.")
    except subprocess.CalledProcessError:
        logger.error("Failed to launch app.")

def wait_for_process(package_name, timeout=10):
    """Waits for the app process to start."""
    logger.info(f"Waiting for process {package_name} to start...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        result = subprocess.run(["adb", "shell", "pidof", package_name], capture_output=True, text=True)
        if result.stdout.strip():
            logger.info(f"Process {package_name} is running.")
            return True
        time.sleep(1)
    logger.error(f"Timeout: {package_name} process not found.")
    return False

def get_bundle_id_from_ipa(ipa_path):
    """Extracts bundle id form .ipa (Info.plist inside Payload)."""
    try:
        subprocess.run(["unzip", "-o", ipa_path, "-d", "temp_ipa_extract"], check=True)
        info_plist = None
        for root, _, files in os.walk("temp_ipa_extract/Payload"):
            for file in files:
                if file == "Info.plist":
                    info_plist = os.path.join(root, file)
                    break
        if info_plist:
            output = subprocess.check_output(["plutil", "-extract", "CFBundleIdentifier", "xml1", "-o", "-", info_plist], text=True)
            return output.strip().split(">")[1].split("<")[0]
    except Exception as e:
        logger.error(f"Failed to extract bundle id: {e}")
    return None

def install_ipa(ipa_path):
    subprocess.run(["ideviceinstaller", "-i", ipa_path])

def uninstall_ipa(bundle_id):
    subprocess.run("ideviceinstaller", "-U", bundle_id)

def launch_ipa_app(bundle_id):
    subprocess.run("idevicedebug", "run", bundle_id)

def wait_for_ios_process(bundle_id, timeout=10):
    logger.info(f"Waiting for iOS app {bundle_id} process to start...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            output = subprocess.check_output(["frida-ps", "-Uai"], text=True)
            if bundle_id in output:
                logger.info(f"iOS App {bundle_id} is running.")
                return True
        except Exception:
            pass
        time.sleep(1)
    logger.error(f"Timeout: {bundle_id} process not found.")
    return False

def run_frida_script(script_path, package_name):
    logger.logtext(f"Running Frida script: {script_path}")
    subprocess.run([
        "frida", "-U", "-n", package_name, "-l", script_path, "--no-pause"
    ])

def start_dynamic_analysis(app_path):
    """Launch dynamic analysis and start traffic interception."""
    logger.info(f"Starting dynamic analysis for {app_path}...")

    device_type = check_device_connection()
    if not device_type:
        return

    ensure_frida_server_running()

    if not frida_helpers.check_frida_version_match():
        logger.error("Aborting dynamic analysis due to the Frida version mismatch.")

    if app_path.endswith(".apk") and device_type == "android":
        package_name = get_package_name_from_apk(app_path)
        main_activity = get_main_activity(app_path)
        if not package_name or not main_activity:
            logger.error("Failed to extract package name - aborting dynamic analysis.")
            return
        
        uninstall_app(package_name)
        subprocess.run(["adb", "install", app_path])
        launch_app(package_name, main_activity)

        if not wait_for_process(package_name):
            return
        
        interceptor = FridaTrafficInterceptor(package_name)
        interceptor.start_hook()
    elif app_path.endswith(".ipa") and device_type == "ios":
        bundle_id = get_bundle_id_from_ipa(app_path)

        if not bundle_id:
            logger.error("Failed to extract bundle id.")
            return
        
        uninstall_app(bundle_id)
        install_ipa(app_path)
        launch_ipa_app(bundle_id)

        if not wait_for_ios_process(bundle_id):
            return
        
        interceptor = FridaTrafficInterceptorIOS(bundle_id)
        interceptor.start_hook()
    else:
        logger.error("Unsupported app format. Only APK supported.")
        return

    logger.info(f"Package name: {package_name}")

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

    logger.info("Frida hooks running. You can interact with the app now.")
    time.sleep(25)

    for t in threads:
        t.join()

    logger.info("Cleaning up Frida hooks...")
    interceptor.stop_hook()

    logger.info("Dynamic analysis finished successfully!")

# NEW: The class wrapper for dynamic analysis

class DynamicAnalysisEngine:
    def __init__(self, app_path):
        self.app_path = app_path

    def start(self):
        start_dynamic_analysis(self.app_path)

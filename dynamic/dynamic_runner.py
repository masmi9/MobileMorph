import os
import sys
import time
import threading
import subprocess
from dynamic.traffic_interceptor import FridaTrafficInterceptor
from dynamic.traffic_interceptor_ios import FridaTrafficInterceptorIOS
from utils import logger, frida_helpers
from dynamic.modules.logcat_monitor import LogcatMonitor
from dynamic.modules.storage_monitor import StorageMonitor

def check_device_connection():
    result = subprocess.check_output("adb devices", shell=True, text=True)
    devices = [line for line in result.splitlines() if "\tdevice" in line]
    if not devices:
        logger.error("No devices/emulators connected. Please connect a device and try again.")
        return None     # No Android device
    logger.info("Detected Android device.")
    return "android"

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
                    if part.startswith("name="):
                        return part.split("=")[1].replace("'", "")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to extract main activity: {e}")
    return None

def get_bundle_id_from_ipa(ipa_path):
    """Extracts bundle id form .ipa (Info.plist inside Payload)."""
    try:
        file = "Info.plist"
        subprocess.run(["unzip", "-o", ipa_path, "-d", "temp_ipa_extract"], check=True)
        for root, _, files in os.walk("temp_ipa_extract/Payload"):
            for file in files:
                plist_path = os.path.join(root, "Info.plist")
                output = subprocess.check_output(["plutil", "-extract", "CFBundleIdentifier", "xml1", "-o", "-", plist_path], text=True)
                return output.strip().split(">")[1].split("<")[0]
    except Exception as e:
        logger.error(f"Failed to extract bundle id: {e}")
    return None

def uninstall_app_android(package_name):
    """Uninstalls the app if it's already installed."""
    logger.info(f"Uninstalling existing app {package_name} (if present)...")
    subprocess.run(["adb", "uninstall", package_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def uninstall_app_ios(bundle_id):
    """Uninstalls the app if it's already installed."""
    logger.info(f"Uninstalling existing app {bundle_id} (if present)...")
    subprocess.run(["ideviceinstaller", "-U", bundle_id])

def launch_app_android(package_name, main_activity):
    logger.info(f"Launching {package_name}/{main_activity}...")
    try:
        subprocess.run(["adb", "shell", "am", "start", "-n", f"{package_name}/{main_activity}"], check=True)
        logger.info("App launched successfully.")
    except subprocess.CalledProcessError:
        logger.error("Failed to launch app.")

def launch_app_ios(bundle_id):
    logger.info(f"Launching iOS app {bundle_id}...")
    subprocess.run(["idevicedebug", "run", bundle_id])

def wait_for_android_process(package_name, timeout=10):
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

def wait_for_ios_process(bundle_id, timeout=10):
    """Waits for the app process to start."""
    logger.info(f"Waiting for process {bundle_id} to start...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            result = subprocess.run(["frida-ps", "-Uai"], text=True)
            if bundle_id in result:
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
        return
    
    app_identifier = None   # Common variable for both apk and ipa

    if app_path.endswith(".apk") and device_type == "android":
        package_name = get_package_name_from_apk(app_path)
        main_activity = get_main_activity(app_path)
        if not package_name or not main_activity:
            logger.error("Failed to extract package name - aborting dynamic analysis.")
            return
        
        app_identifier = package_name

        uninstall_app_android(package_name)
        subprocess.run(["adb", "install", app_path])
        launch_app_android(package_name, main_activity)

        if not wait_for_android_process(package_name):
            return
        
        interceptor = FridaTrafficInterceptor(app_identifier)
        device = interceptor.get_device()

    elif app_path.endswith(".ipa") and device_type == "ios":
        bundle_id = get_bundle_id_from_ipa(app_path)

        if not bundle_id:
            logger.error("Failed to extract bundle id.")
            return
        
        app_identifier = bundle_id
        
        uninstall_app_ios(bundle_id)
        subprocess.run(["ideviceinstaller", "-i", app_path])
        launch_app_ios(bundle_id)

        if not wait_for_ios_process(bundle_id):
            return
        
        # Start Logcat Monitoring here
        logcat_monitor = LogcatMonitor(app_package=app_identifier, output_dir="reports/")
        logcat_monitor.start()
        interceptor = FridaTrafficInterceptorIOS(app_identifier)
        device = interceptor.get_device()

    else:
        logger.error("Unsupported app format. Only APK supported.")
        return

    logger.info(f"Target identifier: {app_identifier}")
    interceptor.start_hook(device=device, timeout=30)

    frida_scripts = [
        "dynamic/frida_hooks/bypass_ssl.js",
        "dynamic/frida_hooks/hook_crypt.js",
        "dynamic/frida_hooks/network_logger.js",
        "dynamic/frida_hooks/auth_bypass.js",
        "dynamic/frida_hooks/root_bypass.js"
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

    # Pull and Scan Storage here
    storage_monitor = StorageMonitor(app_package=app_identifier, output_dir="reports/")
    findings = storage_monitor.run()

    if findings:
        logger.info("Sensitive storage findings detected and stored.")
    else:
        logger.info("No major storage issues found.")

    # Stop Logcat Monitoring
    logcat_monitor.stop()

    logger.info("Cleaning up Frida hooks...")
    interceptor.stop_hook()

    logger.info("Dynamic analysis finished successfully!")

# NEW: The class wrapper for dynamic analysis

class DynamicAnalysisEngine:
    def __init__(self, app_path):
        self.app_path = app_path

    def start(self):
        start_dynamic_analysis(self.app_path)

import os
import sys
import time
import threading
import subprocess
import tempfile
import frida
from pathlib import Path
from dynamic.traffic_interceptor import FridaTrafficInterceptor
from dynamic.traffic_interceptor_ios import FridaTrafficInterceptorIOS
from utils import logger, frida_helpers
from dynamic.modules.logcat_monitor import LogcatMonitor
from dynamic.modules.storage_monitor import StorageMonitor
from dynamic.hook_loader import load_hooks
from dynamic.traffic_analyzer import TrafficAnalyzer
from utils.burp_api_helper import send_url_to_burp, start_burp

FRIDA_AVAILABLE = frida_helpers.FRIDA_AVAILABLE
try:
    FRIDA_AVAILABLE = True
except:
    FRIDA_AVAILABLE = False

def check_device_connection():
    result = subprocess.check_output("adb devices", shell=True, text=True)
    devices = [line for line in result.splitlines() if "\tdevice" in line]
    if not devices:
        logger.error("No devices/emulators connected. Please connect a device and try again.")
        return None
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

        local_frida_path = "tools/frida-server"
        remote_frida_path = "/data/local/tmp/frida-server"

        logger.info("Pushing frida-server to device...")
        subprocess.run(["adb", "push", local_frida_path, remote_frida_path], check=True)

        logger.info("Setting executable permissions...")
        subprocess.run(["adb", "shell", "chmod", "755", remote_frida_path], check=True)

        # Could replace with code below -- Linux
        #logger.info("Starting frida-server with non-blocking exec...")
        #subprocess.run(["adb", "shell", "su", "-c", f"'{remote_frida_path} &'"], check=False)
        #time.sleep(3)  # Give frida-server a moment to start
        # Better --> Windows runner for starting frida-server
        logger.info("Starting frida-server...")
        subprocess.Popen(["adb", "shell", remote_frida_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)

        logger.info("Frida-server started successfully.")
        time.sleep(5)

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start frida-server: {e}")
        sys.exit(1)

def get_package_name_from_apk(apk_path):
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

def uninstall_app_android(package_name):
    logger.info(f"Uninstalling existing app {package_name} (if present)...")
    subprocess.run(["adb", "uninstall", package_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def launch_app_android(package_name, main_activity):
    logger.info(f"Launching {package_name}/{main_activity}...")
    try:
        subprocess.run(["adb", "shell", "am", "start", "-n", f"{package_name}/{main_activity}"], check=True)
        logger.info("App launched successfully.")
    except subprocess.CalledProcessError:
        logger.error("Failed to launch app.")

def wait_for_android_process(package_name, timeout=30):
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

def run_frida_script(script_path, package_name):
    logger.logtext(f"Running Frida script: {script_path}")
    subprocess.run(["frida", "-U", "-n", package_name, "-l", script_path, "--no-pause"])

def start_dynamic_analysis(app_path, hook_profile="minimal"):
    logger.info(f"Starting dynamic analysis for {app_path}...")
    logger.info("Attempting to auto-start Burp Suite...")
    start_burp()

    device_type = check_device_connection()
    if not device_type:
        return

    subprocess.run(["adb", "reverse", "tcp:8080", "tcp:8080"])
    logger.info("Port 8080 reversed for emulator traffic to host.")

    if not FRIDA_AVAILABLE:
        logger.error("Frida is not available or failed to import. Skipping dynamic analysis.")
        return
    
    ensure_frida_server_running()

    if not frida_helpers.check_frida_version_match():
        logger.error("Aborting dynamic analysis due to the Frida version mismatch.")
        return

    app_identifier = None

    if app_path.endswith(".apk") and device_type == "android":
        package_name = get_package_name_from_apk(app_path)
        main_activity = get_main_activity(app_path)
        if not package_name or not main_activity:
            logger.error("Failed to extract package name - aborting dynamic analysis.")
            return

        app_identifier = package_name

        uninstall_app_android(package_name)
        subprocess.run(["adb", "install", app_path], check=True)
        launch_app_android(package_name, main_activity)

        if not wait_for_android_process(package_name):
            return

        interceptor = FridaTrafficInterceptor(app_identifier, output_dir="reports/")
        device = interceptor.get_device()

    else:
        logger.error("Unsupported app format. Only APK supported for dynamic analysis.")
        return

    logger.info(f"Target identifier: {app_identifier}")
    interceptor.start_hook(device=device, timeout=30)

    try:
        frida_scripts = load_hooks(hook_profile)
    except Exception as e:
        logger.error(f"Failed to load hook profile: {e}")
        return

    threads = []
    tmp_paths = []

    for name, content in frida_scripts:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".js") as tmp:
            tmp.write(content.code())
            tmp_path = tmp.name
            tmp_paths.append(tmp_path)

        t = threading.Thread(target=run_frida_script, args=(tmp_path, app_identifier))
        t.start()
        threads.append(t)

    logger.info("Frida hooks running. You can interact with the app now.")
    time.sleep(25)

    for t in threads:
        t.join()

    for tmp_path in tmp_paths:
        os.unlink(tmp_path)

    # STORAGE MONITOR
    storage_monitor = StorageMonitor(app_package=app_identifier, output_dir="reports/")
    findings = storage_monitor.run()

    if findings:
        logger.info("Sensitive storage findings detected and stored.")
    else:
        logger.info("No major storage issues found.")

    # TRAFFIC ANALYZER
    logger.info("Analyzing captured traffic for sensitive data patterns...")
    traffic_log = os.path.join("reports", f"{app_identifier}_traffic_log.txt")
    analyzer = TrafficAnalyzer(traffic_log)
    sensitive_artifacts = analyzer.analyze()

    logger.info("Pushing discovered URLs into BurpSuite for scanning...")

    if sensitive_artifacts:
        unique_urls = set()
        for artifact in sensitive_artifacts:
            if artifact.startswith("http"):
                unique_urls.add(artifact)
        logger.info(f"[+] Found {len(unique_urls)} unique URLs to send to Burp Scanner.")
        # Send each unique URL to Burp Scanner
        for url in unique_urls:
            logger.info(f"[>] Sending {url} to Burp...")
            try:
                send_url_to_burp(url)
                time.sleep(1)  # Optional: Slight delay to avoid flooding Burp API
            except Exception as e:
                logger.warning(f"[!] Failed to send {url} to Burp: {e}")
    else:
        logger.info("No URLs found to push to Burp.")

    # LOGCAT MONITOR CLEANUP
    if 'logcat_monitor' in locals():
        LogcatMonitor.stop()

    logger.info("Cleaning up Frida hooks...")
    interceptor.stop_hook()

    # ---------------- NETWORK TESTING -------------------
    logger.info("[*] Sending target URL to Burp for active scanning...")

    # Typical default address for Android Emulator -> Host mappings
    burp_target = "http://10.0.2.2:8080"  
    try:
        send_url_to_burp(burp_target)
    except Exception as e:
        logger.warning(f"[!] Failed to send target to Burp: {e}")

    logger.info("Dynamic analysis finished successfully!")

class DynamicAnalysisEngine:
    def __init__(self, app_path, hook_profile="minimal"):
        self.app_path = app_path
        self.hook_profile = hook_profile

    def start(self):
        start_dynamic_analysis(self.app_path, self.hook_profile)

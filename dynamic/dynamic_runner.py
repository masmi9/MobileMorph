import time
import threading
import subprocess
from dynamic.traffic_interceptor import TrafficInterceptor
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
                # Example:
                parts = line.split()
                for part in parts:
                    if part.startswith("name="):
                        return part.split("=")[1].replace("'", "")
    except subprocess.CalledProcessError as e:
        logger.error(f"[X] Failed to extract package name: {e}")
    return None

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

    # Start the traffic interceptor
    interceptor = TrafficInterceptor()
    proxy_port = 8080
    interceptor.start_proxy(port=proxy_port)

    # You can automate the process to launch the app, e.g., for Android:
    if app_path.endswith(".apk"):
        subprocess.run(["adb", "install", app_path])  # Install APK to device
        package_name = get_package_name_from_apk(app_path)
        if not package_name:
                logger.error("Failed to extract package name - aborting dynamic analysis.")
                return
        subprocess.run(["adb", "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"])
    elif app_path.endswith(".ipa"):
        # iOS app handling (you may use a tool like Appium or manual steps here)
        logger.warning("iOS dynamic suport not implemented yet.")
        return
    else:
        logger.error("Unsupported app format. Only APK and IPA are supported.")
        return
    
    logger.info(f"Package name: {package_name}")

    frida_scripts = [
        "dynamic/frida_hooks/bypass_ssl.js",
        "dynamic/frida_hooks/hook_crypt.js"
    ]

    # Run Frida hooks
    threads = []
    for script in frida_scripts:
        t = threading.Thread(target=run_frida_script, args=(script, package_name))
        t.start()
        threads.append(t)

    logger.info("[*] Frida hooks running. You can interact with the app now.")
    time.sleep(30)  # Let the analysis run for 30 seconds (adjust as needed)

    for t in threads:
        t.join()

    logger.info("Dynamic analysis started successfully!")

if __name__ == "__main__":
    import sys
    start_dynamic_analysis(sys.argv[1])

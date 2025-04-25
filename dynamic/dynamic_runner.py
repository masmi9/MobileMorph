import os
import time
import threading
import subprocess
from dynamic.traffic_interceptor import TrafficInterceptor
from utils import logger

def run_frida_script(script_path, package_name):
    print(f"[*] Running Frida script: {script_path}")
    subprocess.run([
        "frida", "-U", "-n", package_name, "-l", script_path, "--no-pause"
    ])

def start_dynamic_analysis(app_path, proxy_port=8080):
    """Launch dynamic analysis and start traffic interception."""
    logger.info(f"Starting dynamic analysis for {app_path}...")

    # Start the traffic interceptor
    interceptor = TrafficInterceptor()
    interceptor.start_proxy(port=proxy_port)

    frida_scripts = [
        "dynamic/frida_hooks/bypass_ssl.js",
        "dynamic/frida_hooks/hook_crypt.js"
    ]

    # You can automate the process to launch the app, e.g., for Android:
    if app_path.endswith(".apk"):
        subprocess.run(["adb", "install", app_path])  # Install APK to device
        subprocess.run(["adb", "shell", "am", "start", "-n", "com.example/.MainActivity"])  # Launch the app
    elif app_path.endswith(".ipa"):
        # iOS app handling (you may use a tool like Appium or manual steps here)
        pass
    else:
        logger.error("Unsupported app format. Only APK and IPA are supported.")
        return

    threads = []
    for script in frida_scripts:
        t = threading.Thread(target=run_frida_script, args=(script, package_name))
        t.start()
        threads.append(t)

    print("[*] Frida hooks running. You can interact with the app now.")
    time.sleep(30)  # Let the analysis run for 30 seconds (adjust as needed)

    for t in threads:
        t.join()

    logger.info("Dynamic analysis started successfully!")

if __name__ == "__main__":
    import sys
    start_dynamic_analysis(sys.argv[1])

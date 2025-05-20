import os
import frida
import sys
import threading
import time
from utils import logger, paths
from dynamic.hook_loader import load_hooks

class FridaTrafficInterceptorIOS:
    def __init__(self, bundle_id):
        self.bundle_id = bundle_id
        self.session = None
        self.script = None
        self.traffic_log_file = None

    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            logger.info(f"[Frida Hook] {payload}")
            if self.traffic_log_file:
                with open(self.traffic_log_file, "a", encoding="utf-8") as f:
                    f.write(payload + "\n")
        elif message['type'] == 'error':
            logger.error(f"[Frida Error] {message}")

    def get_device(self):
        try:
            device = frida.get_usb_device()
            logger.info("Connected to iOS device over USB.")
            return device
        except Exception as e:
            logger.error(f"Failed to connect to iOS device: {str(e)}")
            sys.exit(1)

    def start_hook(self, profile="ios_full", timeout=30):
        try:
            device = self.get_device()
            logger.info(f"Attaching to iOS app {self.bundle_id} on device {device.name}...")

            # Setup traffic log file
            output_folder = paths.get_output_folder()
            traffic_logs_dir = os.path.join(output_folder, "traffic_logs")
            os.makedirs(traffic_logs_dir, exist_ok=True)
            self.traffic_log_file = os.path.join(traffic_logs_dir, f"{self.bundle_id}_traffic.txt")

            # Wait for process to appear
            start_time = time.time()
            while time.time() - start_time < timeout:
                processes = device.enumerate_processes()
                target = next((p for p in processes if self.bundle_id.lower() in p.name.lower()), None)
                if target:
                    break
                logger.info("Waiting for app process to start...")
                time.sleep(1)
            else:
                logger.error(f"Process {self.bundle_id} not found after waiting.")
                sys.exit(1)

            self.session = device.attach(target.pid)
            logger.info(f"Attached to PID {target.pid} for {self.bundle_id}.")

            # Load Frida script
            hooks = load_hooks(profile)
            logger.info(f"Loaded {len(hooks)} Frida hook(s) from profile '{profile}'")

            for name, code in hooks:
                script = self.session.create_script(code)
                script.on("message", self.on_message)
                script.load()
                self.scripts.append(script)
                logger.info(f"Injected hook: {name}")

            logger.info("Frida hook injected successfully. Monitoring traffic...")
            threading.Event().wait()

        except Exception as e:
            logger.error(f"Failed to hook into {self.bundle_id}: {str(e)}")
            sys.exit(1)

    def stop_hook(self):
        try:
            for script in self.script:
                script.unload()
            logger.info("Unloaded Frida script.")
            if self.session:
                self.session.detach()
                logger.info("Detached from app process.")
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

# Optional CLI runner for testing
#if __name__ == "__main__":
#    if len(sys.argv) < 2:
#        print("Usage: python traffic_interceptor_ios.py <bundle_id> [profile_name]")
#        sys.exit(1)
#
#    bundle_id = sys.argv[1]
#    profile = sys.argv[2] if len(sys.argv) > 2 else "ios_full"
#
#    interceptor = FridaTrafficInterceptorIOS(bundle_id)
#    interceptor.start_hook(profile=profile)
import frida
import sys
import threading
import time
from utils import logger

class FridaTrafficInterceptorIOS:
    def __init__(self, bundle_id):
        self.bundle_id = bundle_id
        self.session = None
        self.script = None

    def on_message(self, message, data):
        if message['type'] == 'send':
            logger.info(f"[Frida Hook] {message['payload']}")
        elif message['type'] == 'error':
            logger.error(f"[Frida Error] {message}")

    def get_device(self):
        try:
            device = frida.get_usb_device()
            logger.info("[+] Connected to iOS device over USB.")
            return device
        except Exception as e:
            logger.error(f"[X] Failed to connect to iOS device: {str(e)}")
            sys.exit(1)

    def start_hook(self):
        try:
            logger.info(f"[*] Attaching to iOS app {self.bundle_id}...")

            device = self.get_device()

            # Wait for process to appear
            for _ in range(10):
                processes = device.enumerate_processes()
                target = next((p for p in processes if self.bundle_id in p.name), None)
                if target:
                    break
                logger.info("[*] Waiting for app process to start...")
                time.sleep(1)
            else:
                logger.error(f"[X] Process {self.bundle_id} not found after waiting.")
                sys.exit(1)

            self.session = device.attach(target.pid)
            logger.info(f"[+] Attached to PID {target.pid} for {self.bundle_id}.")

            with open("dynamic/frida_hooks/network_logger.js") as f:
                script_code = f.read()

            self.script = self.session.create_script(script_code)
            self.script.on("message", self.on_message)
            self.script.load()

            logger.info("[+] Frida hook injected successfully. Monitoring traffic...")
            # Keep process alive
            threading.Event().wait()

        except Exception as e:
            logger.error(f"[X] Failed to hook into {self.bundle_id}: {str(e)}")
            sys.exit(1)

    def stop_hook(self):
        try:
            if self.script:
                self.script.unload()
                logger.info("Unloaded Frida script.")
            if self.session:
                self.session.detach()
                logger.info("Detached from app process.")
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
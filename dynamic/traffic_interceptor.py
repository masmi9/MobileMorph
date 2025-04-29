import frida
import sys
import threading
import time
import os
from utils import logger
from dynamic.traffic_analyzer import TrafficAnalyzer
from datetime import datetime

class FridaTrafficInterceptor:
    def __init__(self, package_name, output_dir):
        self.package_name = package_name
        self.session = None
        self.script = None
        self.hook_event = threading.Event()
        self.traffic_log_path = os.path.join(output_dir, f"{package_name}_traffic_log.txt")

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            logger.info(f"[Frida Hook] {payload}")
            self.save_traffic(payload)
        elif message['type'] == 'error':
            logger.error(f"[Frida Error] {message}")

    def save_traffic(self, payload):
        try:
            with open(self.traffic_log_path, "a", encoding="utf-8") as f:
                f.write(payload + "\n")
        except Exception as e:
            logger.error(f"Failed to save traffic: {str(e)}")

    def get_device(self):
        try:
            manager = frida.get_device_manager()
            devices = manager.enumerate_devices()
            # Try to USB device if remote is not available
            if not devices:
                logger.error("No suitable Android Frida device found. Exiting.")
                sys.exit(1)
            for device in devices:
                if device.type not in ("usb", "remote"): 
                    continue # Skip local PC devices
                logger.info(f"Selecting Frida device: {device.name} for {self.package_name}...")
                
                try:
                    processes = device.enumerate_processes()
                    for process in processes:
                        if self.package_name.lower() in process.name.lower():
                            logger.info(f"Found {self.package_name} running on device {device.name} ({device.type})!")
                            return device
                except Exception as e:
                    logger.warning(f"Failed to enumerate processes on {device.name}: {str(e)}")
            logger.error(f"No Frida device: found {str(e)}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Could not find {self.package_name} on any connected devices. Make sure the app is running.")
            sys.exit(1)

    def list_frida_devices(self):
        """Lists all available Frida devices and their processes."""
        try:
            manager = frida.get_device_manager()
            devices = manager.enumerate_devices()

            if not devices:
                logger.error("No devices detected. Please ensure your device is connected.")
                return False

            logger.info("Connected Frida Devices:")
            for device in devices:
                logger.info(f"Device: {device.name} (Type: {device.type})")

                try:
                    processes = device.enumerate_processes()
                    logger.info(f"  Processes on {device.name}:")
                    for process in processes:
                        logger.info(f"    {process.name} - {process.pid}")
                except Exception as e:
                    logger.error(f"  Error retrieving processes: {str(e)}")

            return True  # Devices found
        except Exception as e:
            logger.error(f"Failed to list devices: {str(e)}")
            return False

    def start_hook(self, device, timeout=30):
        try:
            # List devices and ensure Frida is connected properly
            if not self.list_frida_devices():
                logger.error("No Frida devices detected. Exiting.")
                sys.exit(1)

            logger.info(f"Attaching to {self.package_name} on device {device.name}...")

            #device = self.get_device()

            # Wait for process to appear
            start_time = time.time()
            while time.time() - start_time < timeout:
                processes = device.enumerate_processes()
                target = next((p for p in processes if self.package_name.lower() in p.name.lower()), None)
                if target:
                    break
                logger.info("Waiting for app process to start...")
                time.sleep(1)
            else:
                logger.error(f"Process {self.package_name} not found after waiting.")
                sys.exit(1)

            self.session = device.attach(target.pid)
            logger.info(f"Attached to PID {target.pid} for {self.package_name}")

            # Load upgraded Frida HTTP logger
            with open("dynamic/frida_hooks/network_logger.js") as f:
                script_code = f.read()
            
            # Inject a default simple network hook (can be expanded to pass custom script)
            self.script = self.session.create_script(script_code)
            self.script.on("message", self.on_message)
            self.script.load()

            logger.info("Frida hook injected successfully. Monitoring traffic...")
            threading.Event().wait()

        except Exception as e:
            logger.error(f"Failed to hook into {self.package_name}: {str(e)}")
            sys.exit(1)

    def load_frida_script(self, script_path):
        """Load a specific Frida script dynamically."""
        try:
            with open(script_path) as f:
                script_code = f.read()

            self.script = self.session.create_script(script_code)
            self.script.on("message", self.on_message)
            self.script.load()

            logger.info(f"Loaded Frida script: {script_path}")
            self.hook_event.wait()  # Control when to clean up
        except Exception as e:
            logger.error(f"Failed to load Frida script: {str(e)}")
            sys.exit(1)

    def stop_hook(self):
        try:
            if self.script:
                self.script.unload()
                logger.info("Unloaded Frida script.")
            if self.session:
                self.session.detach()
                logger.info("Detached from app process.")

            # Analyze captured traffic after stop
            logger.info("Starting traffic analysis...")
            TrafficAnalyzer.analyze_traffic(self.traffic_log_path)

        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

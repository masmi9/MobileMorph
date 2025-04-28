import frida
import sys
import threading
import time
from utils import logger

class FridaTrafficInterceptor:
    def __init__(self, package_name):
        self.package_name = package_name
        self.session = None
        self.script = None
    
    def on_message(self, message, data):
        if message['type'] == 'send':
            logger.info(f"[Frida Hook] {message['payload']}")
        elif message['type'] == 'error':
            logger.error(f"[Frida Error] {message}")

    def get_device(self):
        try:
            # Try to USB device if remote is not available
            device = frida.get_usb_device()
            logger.info("Connected to USB Frida device.")
        except Exception:
            # Fallback to remote device
            logger.warning("USB device not found. Trying remote device...")
            try:
                device = frida.get_remote_device()
                logger.info("Connected to remote Frida device.")
            except Exception as e:
                logger.error(f"No Frida device: found {str(e)}")
                sys.exit(1)
        return device

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

    def start_hook(self):
        try:
            # List devices and ensure Frida is connected properly
            if not self.list_frida_devices():
                logger.error("No Frida devices detected. Exiting.")
                sys.exit(1)

            logger.info(f"Attaching to {self.package_name}...")

            device = self.get_device()

            # Wait for process to appear
            for _ in range(10):
                processes = device.enumerate_processes()
                target = next((p for p in processes if self.package_name in p.name), None)
                if target:
                    break
                logger.info("Waiting for app process to start...")
                time.sleep(1)
            else:
                logger.error(f"Process {self.package_name} not found after waiting.")
                sys.exit(1)

            self.session = device.attach(target.pid)
            logger.info(f"Attached to PID {target.pid}")

            with open("dynamic/frida_hooks/network_logger.js") as f:
                script_code = f.read()

            self.script = self.session.create_script(script_code)
            self.script.on("message", self.on_message)
            self.script.load()

            logger.info("Frida hook injected successfully. Monitoring traffic...")
            # Keep the process alive for Frida messages
            threading.Event().wait()

        except Exception as e:
            logger.error(f"Failed to hook into {self.package_name}: {str(e)}")
            sys.exit(1)

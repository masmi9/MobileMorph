import frida
import sys
import threading
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

    def start_hook(self):
        try:
            logger.info(f"Attaching to {self.package_name}...")
            self.session = frida.get_usb_device().attach(self.package_name)

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
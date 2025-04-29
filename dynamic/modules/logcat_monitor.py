# dynamic/modules/logcat_monitor.py

import subprocess
import threading
import re
import time
import os
from utils.logger import logger  # Use your existing logger

class LogcatMonitor:
    def __init__(self, app_package, output_dir="reports/"):
        self.app_package = app_package
        self.output_dir = output_dir
        self.sensitive_patterns = [
            re.compile(r"(?i)password\s*[:=]\s*\S+"),
            re.compile(r"(?i)auth\s*[:=]\s*\S+"),
            re.compile(r"(?i)token\s*[:=]\s*\S+"),
            re.compile(r"(?i)apikey\s*[:=]\s*\S+"),
            re.compile(r"(?i)jwt\s*[:=]\s*\S+"),
            re.compile(r"(?i)session\s*[:=]\s*\S+"),
            re.compile(r"(?i)card\s*number\s*[:=]\s*\d+"),
            re.compile(r"(?i)pin\s*[:=]\s*\d{4,6}"),
        ]
        self.keep_running = False
        self.logcat_thread = None
        self.log_file_path = os.path.join(self.output_dir, f"logcat_capture_{int(time.time())}.txt")

    def _monitor_logcat(self):
        logger.info(f"[*] Starting logcat monitor for package: {self.app_package}")
        with open(self.log_file_path, "w") as log_file:
            try:
                logcat_proc = subprocess.Popen(
                    ["adb", "logcat", f"*:{'D'}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=1,
                    universal_newlines=True
                )

                for line in logcat_proc.stdout:
                    if not self.keep_running:
                        break

                    if self.app_package in line:
                        for pattern in self.sensitive_patterns:
                            if pattern.search(line):
                                logger.warning(f"[!] Sensitive data found: {line.strip()}")
                                log_file.write(line)

            except Exception as e:
                logger.error(f"[-] Logcat monitoring error: {e}")

    def start(self):
        self.keep_running = True
        self.logcat_thread = threading.Thread(target=self._monitor_logcat, daemon=True)
        self.logcat_thread.start()

    def stop(self):
        self.keep_running = False
        if self.logcat_thread is not None:
            self.logcat_thread.join()
        logger.info("[*] Logcat monitoring stopped.")


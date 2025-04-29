# dynamic/modules/storage_monitor.py

import subprocess
import os
import re
import shutil
import time
from utils.logger import logger  # Use your existing logger

class StorageMonitor:
    def __init__(self, app_package, output_dir="reports/"):
        self.app_package = app_package
        self.output_dir = output_dir
        self.sandbox_pull_dir = os.path.join(self.output_dir, f"sandbox_dump_{int(time.time())}")

    def pull_app_data(self):
        logger.info(f"Pulling app data for package: {self.app_package}")
        try:
            # Create output dir
            os.makedirs(self.sandbox_pull_dir, exist_ok=True)

            # Run adb pull
            pull_cmd = f"adb exec-out run-as {self.app_package} tar c ./ | tar x -C {self.sandbox_pull_dir}"
            subprocess.run(pull_cmd, shell=True, check=True)

            logger.info(f"Pulled app data into: {self.sandbox_pull_dir}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to pull app data: {e}")
        except Exception as e:
            logger.error(f"Error: {e}")

    def scan_for_sensitive_data(self):
        logger.info("Scanning pulled files for sensitive information...")
        sensitive_patterns = [
            re.compile(r"(?i)(api_key|apikey|token|password|secret|auth)[\"']?\s*[:=]\s*[\"']?[\w\d\-]+"),
            re.compile(r"(?i)eyJ[a-zA-Z0-9-_]+\.")  # JWT tokens pattern
        ]
        findings = []
        for root, dirs, files in os.walk(self.sandbox_pull_dir):
            for file in files:
                if file.endswith((".xml", ".json", ".txt", ".db", ".prefs")):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            for pattern in sensitive_patterns:
                                matches = pattern.findall(content)
                                if matches:
                                    logger.warning(f"[!] Sensitive data found in {file_path}")
                                    findings.append({
                                        "file": file_path,
                                        "matches": matches
                                    })
                    except Exception as e:
                        logger.error(f"[-] Failed to scan file {file_path}: {e}")
        return findings
    
    def run(self):
        self.pull_app_data()
        findings = self.scan_for_sensitive_data()
        return findings
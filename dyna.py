#!/usr/bin/env python3

import os
import subprocess
import re
import logging
import shutil
import time
import sys
from xml.dom.minidom import parseString
import argparse


logging.basicConfig(
    level=logging.INFO,  # Change to DEBUG for more verbosity
    format='[%(levelname)s] %(message)s'
)

# color codes
COLOR_RESET = "\033[0m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_BLUE = "\033[94m"
COLOR_WHITE = "\033[97m"
COLOR_CYAN = "\033[96m"

def colorize_text(text, color):

    return f"{color}{text}{COLOR_RESET}"

def colorize_section_titles(output):

    section_patterns = [
        r"Shared User ID:",
        r"Uses Permissions:",
        r"Defines Permissions:",
        r"Application Label:",
        r"Process Name:",
        r"Version:",
        r"Data Directory:",
        r"APK Path:",
        r"UID:",
        r"GID:",
        r"Shared Libraries:",
        r"Authority:",
        r"Read Permission:",
        r"Write Permission:",
        r"Content Provider:",
        r"Multiprocess Allowed:",
        r"Grant Uri Permissions:",
        r"Uri Permission Patterns:",
        r"Path Permissions:",
        r"Selecting .* \([^\)]+\)",
        r"Attempting to run shell module",
        r"Package: .*",
        r"Injection in Projection:",
        r"Injection in Selection:",
        r"[INFO] Testing Authorization & Privilege Escalation...",
        r"[INFO] Extracting Deeplinks and URLs from the APK...",
        r"[INFO] Testing Content Providers for basic SQL Injection Vulns...",
        r"[INFO] Testing Authorization & Privilege Escalation..."

    ]


    for pattern in section_patterns:
        output = re.sub(pattern, lambda m: colorize_text(m.group(0), COLOR_CYAN), output)


    vulnerability_patterns = [
        r"\[!\] Potential input handling issues detected via injection tests\.",
        r"\[!\] Insecure providers detected:",
        r"\[!\] Failed to access shared_prefs or no secrets found:.*",
        r"\[!\] Command '.*' failed:.*",
        r"\[!\] Injection possible",
        r"\[!\] Vulnerable",
        r"\[!\] Potential plaintext keys or secrets found:"
    ]
    for pattern in vulnerability_patterns:
        output = re.sub(pattern, lambda m: colorize_text(m.group(0), COLOR_RED), output)

    no_vulnerability_patterns = [
        r"\[+\] No plaintext keys or secrets found in shared_prefs\.",
        r"\[+\] App is not debuggable\.",
        r"\[+\] No insecure providers found, authorization checks passed\.",
        r"\[+\] No obvious input handling issues detected via injection tests\.",
        r"\[+\] No deep links found\.",
        r"\[+\] No URLs found\.",
        r"\[+\] No IP addresses found\."
    ]
    for pattern in no_vulnerability_patterns:
        output = re.sub(pattern, lambda m: colorize_text(m.group(0), COLOR_GREEN), output)


    warning_patterns = [
        r"\[!\] Injection test inconclusive\. Please verify manually\."
    ]
    for pattern in warning_patterns:
        output = re.sub(pattern, lambda m: colorize_text(m.group(0), COLOR_YELLOW), output)

    return output

def print_banner():
    os.system('clear')
    banner = """
DDD:::::DDDDD:::::D
D::::::::::::DDD
D:::::::::::::::DD
DDD:::::DDDDD:::::D
  D:::::D    D:::::Dyyyyyyy           yyyyyyynnnn  nnnnnnnn      aaaaaaaaaaaaa
  D:::::D     D:::::Dy:::::y         y:::::y n:::nn::::::::nn    a::::::::::::a
  D:::::D     D:::::D y:::::y       y:::::y  n::::::::::::::nn   aaaaaaaaa:::::a
  D:::::D     D:::::D  y:::::y     y:::::y   nn:::::::::::::::n           a::::a
  D:::::D     D:::::D   y:::::y   y:::::y      n:::::nnnn:::::n    aaaaaaa:::::a
  D:::::D     D:::::D    y:::::y y:::::y       n::::n    n::::n  aa::::::::::::a
  D:::::D     D:::::D     y:::::y:::::y        n::::n    n::::n a::::aaaa::::::a
  D:::::D    D:::::D       y:::::::::y         n::::n    n::::na::::a    a:::::a
DDDD:::::DDDDD:::::D         y:::::::y          n::::n    n::::na::::a    a:::::a
D:::::::::::::::DD           y:::::y           n::::n    n::::n a:::::aaaa::::::a
D::::::::::::DDD            y:::::y            n::::n    n::::n a::::::::::aa:::a
DDDDDDDDDDDDDDDDD          y:::::y             nnnnnn    nnnnnn  aaaaaaaaaa  aaaa
                          y:::::y
                         y:::::y
                        y:::::y
                       y:::::y
                      yyyyyyy
                               """
    print(colorize_text(banner, COLOR_BLUE))

def run_logcat_monitor(package_name):
    """
    This will Run the adb logcat command to monitor logs for the given package in a new terminal window.
    """

    ip_regex = r'\b(?:(?:2[0-4]\d|25[0-5]|1\d{2}|[1-9]?\d)\.){3}(?:2[0-4]\d|25[0-5]|1\d{2}|[1-9]?\d)\b|(?:\b[A-F0-9]{1,4}:(?:[A-F0-9]{1,4}:){5}[A-F0-9]{1,4}\b)'


    combined_regex = f'({ip_regex})|token|key|password|db|database|http://|https://|ip address'


    cmd = (
        f"adb logcat | grep --line-buffered '{package_name}' "
        f"| tee log_output.txt | grep --line-buffered -E --color=always -i '{combined_regex}'"
    )

    logging.info("Starting logcat monitor. This will run in a separate terminal if available.")
    if shutil.which("xterm"):
        subprocess.Popen(['xterm', '-geometry', '200x80+50+50', '-e', 'bash', '-c', cmd], close_fds=True)
    elif shutil.which("xfce4-terminal"):
        subprocess.Popen(['xfce4-terminal', '-e', f"bash -c \"{cmd}\""], close_fds=True)
    elif shutil.which("gnome-terminal"):
        subprocess.Popen(['gnome-terminal', '--geometry=100x40+50+50', '--', 'bash', '-c', cmd], close_fds=True)
    else:
        logging.warning("No graphical terminal found. Running logcat monitor in the background.")
        subprocess.Popen(['bash', '-c', cmd], close_fds=True)


    print(colorize_text("Log monitor started, continuing main script execution...", COLOR_BLUE))


class DrozerHelper:


    def __init__(self, package_name):
        self.package_name = package_name

    def start_drozer(self):
        """Starting Drozer and set up port forwarding."""
        logging.info(colorize_text("Starting Drozer...", COLOR_YELLOW))
        subprocess.run(["adb", "forward", "--remove", "tcp:31415"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Forward the port
        result = subprocess.run(["adb", "forward", "tcp:31415", "tcp:31415"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            logging.info(colorize_text("Port forwarding set up successfully.", COLOR_GREEN))
        else:
            logging.error(f"Failed to set up port forwarding: {result.stderr}")
            print(colorize_text("[!] Failed to set up port forwarding for Drozer.", COLOR_RED))
            sys.exit(1)

    def check_connection(self):

        try:
            output = subprocess.check_output(
                "drozer console connect --command 'run app.package.list'",
                shell=True, stderr=subprocess.STDOUT, universal_newlines=True
            )
            if "No devices connected" in output or "not found" in output:
                print(colorize_text("[!] Drozer not connected. Please check device connection and try again.", COLOR_RED))
                return False
            print(colorize_text("[*] Drozer connected successfully.", COLOR_GREEN))
            return True
        except subprocess.CalledProcessError as e:

            error_message = e.output.strip() if e.output else "Unknown error occurred."
            print(colorize_text(f"[!] Drozer connection failed: {error_message}", COLOR_RED))
            return False

    def run_command(self, command):
        """Run Drozer"""
        full_command = f"drozer console connect --command '{command}'"
        try:
            logging.debug(f"Running Drozer command: {command}")
            output = subprocess.check_output(
                full_command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True
            )
            return colorize_section_titles(output)
        except subprocess.CalledProcessError as e:
            error_message = e.output.strip() if e.output else "Unknown error occurred."
            logging.error(f"Command '{command}' failed: {error_message}")
            return colorize_text(f"[!] Command '{command}' failed: {error_message}", COLOR_RED)

class APKAnalyzer:

    def __init__(self, manifest_dir, decompiled_dir):
        self.decompiled_dir = decompiled_dir
        self.manifest_file = os.path.join(manifest_dir, 'AndroidManifest.xml')
        self.strings_file = os.path.join(manifest_dir, 'res', 'values', 'strings.xml')
        self.strings_dict = {}
        self._parse_strings()

    def _parse_strings(self):
        if os.path.exists(self.strings_file):
            try:
                with open(self.strings_file, 'r', encoding='utf8', errors='ignore') as f:
                    content = f.read()
                dom = parseString(content)
                strings = dom.getElementsByTagName('string')
                for string in strings:
                    name = string.getAttribute('name')
                    value = string.firstChild.nodeValue if string.firstChild else ''
                    self.strings_dict[name] = value
            except Exception as e:
                logging.error(f"Error parsing strings.xml: {str(e)}")

    def resolve_string(self, value):
        if value.startswith('@string/'):
            key = value.split('/')[1]
            return self.strings_dict.get(key, value)
        return value

    def validate_manifest(self):
        if not os.path.exists(self.manifest_file):
            logging.error(f"Manifest file not found: {self.manifest_file}")
            return False
        try:
            with open(self.manifest_file, 'r', encoding='utf8', errors='ignore') as f:
                content = f.read()
            if not content.strip().startswith("<?xml"):
                logging.error("Manifest file is not valid XML.")
                return False
            parseString(content)
            logging.info("Manifest file is valid and well-formed.")
            return True
        except Exception as e:
            logging.error(f"Manifest validation failed: {str(e)}")
            return False

    def extract_deeplinks(self):
        """Extracting deep links from AndroidManifest.xml."""
        deeplinks = set()
        if not self.validate_manifest():
            return deeplinks
        try:
            with open(self.manifest_file, 'r', encoding='utf8', errors='ignore') as f:
                content = f.read()
            dom = parseString(content)
            activities = dom.getElementsByTagName('activity') + dom.getElementsByTagName('activity-alias')
            for activity in activities:
                intent_filters = activity.getElementsByTagName('intent-filter')
                for intent in intent_filters:
                    data_tags = intent.getElementsByTagName('data')
                    for data in data_tags:
                        scheme = self.resolve_string(data.getAttribute('android:scheme')) if data.hasAttribute('android:scheme') else ''
                        host = self.resolve_string(data.getAttribute('android:host')) if data.hasAttribute('android:host') else ''
                        path = self.resolve_string(data.getAttribute('android:path')) if data.hasAttribute('android:path') else ''
                        port = self.resolve_string(data.getAttribute('android:port')) if data.hasAttribute('android:port') else ''
                        path_prefix = self.resolve_string(data.getAttribute('android:pathPrefix')) if data.hasAttribute('android:pathPrefix') else ''
                        path_pattern = self.resolve_string(data.getAttribute('android:pathPattern')) if data.hasAttribute('android:pathPattern') else ''

                        deeplink = ""
                        if scheme and host:
                            deeplink = f"{scheme}://{host}"
                            if port:
                                deeplink += f":{port}"
                            if path:
                                deeplink += path
                            elif path_prefix:
                                deeplink += path_prefix + "*"
                            elif path_pattern:
                                deeplink += path_pattern
                            if deeplink:
                                deeplinks.add(deeplink)
            return deeplinks
        except Exception as e:
            logging.error(f"Failed to parse AndroidManifest.xml: {str(e)}")
            return deeplinks

    def extract_urls(self):
        """Extract URLs and IP addresses from decompiled code."""
        urls, ip_addresses = set(), set()
        relevant_extensions = ('.smali', '.xml', '.txt', '.html', '.js')
        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(relevant_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf8', errors='ignore') as f:
                            for line in f:
                                urls_in_line = re.findall(r'https?://[^\s<>"\']+', line)
                                urls.update(urls_in_line)
                                ips_in_line = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                                ip_addresses.update(ips_in_line)
                    except Exception as e:
                        logging.debug(f"Error reading file {file_path}: {str(e)}")
        return urls, ip_addresses

class OWASPTestSuiteDrozer:
    def __init__(self, apk_path, package_name):
        self.apk_path = apk_path
        self.package_name = package_name
        self.drozer = DrozerHelper(self.package_name)
        self.report_data = []

    def start_drozer(self):
        self.drozer.start_drozer()

    def check_drozer_connection(self):
        return self.drozer.check_connection()

    def unpack_apk(self):
        logging.info(colorize_text("Unpacking APK for analysis...", COLOR_YELLOW))
        os.system(f"apktool d {self.apk_path} -o ./decompiled_app/")
        # Verifying if AndroidManifest.xml exists
        manifest_path = "./decompiled_app/AndroidManifest.xml"
        if not os.path.exists(manifest_path):
            logging.error("AndroidManifest.xml not found after unpacking.")
            print(colorize_text("[!] AndroidManifest.xml not found after unpacking. Exiting.", COLOR_RED))
            sys.exit(1)
        logging.info("APK unpacked successfully.")

    def add_report_section(self, title, content):
        """Add a section to the report data."""
        self.report_data.append((title, content))

    def improper_platform_usage(self):
        logging.info(colorize_text("Checking for Improper Platform Usage...", COLOR_YELLOW))
        drozer_cmds = [
            f"run app.package.info -a {self.package_name}",
            f"run app.activity.info -a {self.package_name}",
            f"run app.broadcast.info -a {self.package_name}",
            f"run app.provider.info -a {self.package_name}"
        ]

        results = []
        for cmd in drozer_cmds:
            output = self.drozer.run_command(cmd)
            print(colorize_text(output, COLOR_WHITE))
            results.append(output)

        self.add_report_section("M1: Improper Platform Usage", "\n".join(results))

    def attack_surface_analysis(self):
        logging.info(colorize_text("Performing In-Depth Attack Surface Analysis...", COLOR_YELLOW))
        commands = [
            f"run app.activity.info -a {self.package_name}",
            f"run app.service.info -a {self.package_name}",
            f"run app.broadcast.info -a {self.package_name}",
            f"run app.provider.info -a {self.package_name}",
            f"run app.package.attacksurface {self.package_name}"
        ]
        results = []
        for cmd in commands:
            output = self.drozer.run_command(cmd)
            print(colorize_text(output, COLOR_WHITE))
            results.append(output)

        self.add_report_section("Attack Surface Analysis", "\n".join(results))

    def insecure_data_storage(self):
        logging.info(colorize_text("Running Insecure Data Storage Test...", COLOR_YELLOW))
        # Corrected Drozer command with '-a' flag
        content_providers = self.drozer.run_command(f"run app.provider.finduri -a {self.package_name}")
        print(colorize_text(content_providers, COLOR_WHITE))
        self.add_report_section("Insecure Data Storage", content_providers)

        run_as_command = f"adb shell su 0 ls /data/data/{self.package_name}/shared_prefs"
        run_as_result = subprocess.run(run_as_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if run_as_result.returncode == 0:
            shared_prefs = run_as_result.stdout.strip()
            if shared_prefs:
                shared_prefs_output = f"{colorize_text('[+] Shared Preferences found:', COLOR_GREEN)}\n{shared_prefs}"
                print(colorize_text(shared_prefs_output, COLOR_GREEN))
                self.add_report_section("Shared Preferences", shared_prefs_output)
            else:
                shared_prefs_output = f"{colorize_text('[!] No Shared Preferences found.', COLOR_YELLOW)}"
                print(shared_prefs_output)
                self.add_report_section("Shared Preferences", shared_prefs_output)
        else:
            error_output = run_as_result.stderr.strip()
            shared_prefs_output = f"{colorize_text('[!] Failed to list shared_prefs:', COLOR_RED)} {error_output}"
            print(shared_prefs_output)
            self.add_report_section("Shared Preferences", shared_prefs_output)

    def traversal_vulnerabilities(self):
        logging.info(colorize_text("Testing Content Providers for Traversal Vulns...", COLOR_YELLOW))
        content_providers = self.drozer.run_command(f"run scanner.provider.traversal -a {self.package_name}")
        print(colorize_text(content_providers, COLOR_WHITE))
        self.add_report_section("Traversal Vulnerabilities", content_providers)

    def injection_vulnerabilities(self):
        logging.info(colorize_text("Testing Content Providers for basic SQL Injection Vulns...", COLOR_YELLOW))
        content_providers = self.drozer.run_command(f"run scanner.provider.injection -a {self.package_name}")
        print(colorize_text(content_providers, COLOR_WHITE))
        self.add_report_section("Injection Vulnerabilities", content_providers)

    def extract_additional_info(self):
        logging.info(colorize_text("Extracting Deeplinks and URLs from the APK...", COLOR_YELLOW))
        analyzer = APKAnalyzer("./decompiled_app", "./decompiled_app")
        deeplinks = analyzer.extract_deeplinks()
        results = []
        if deeplinks:
            deeplinks_formatted = "\n".join(deeplinks)
            results.append(f"{colorize_text('[+] Deep Links Found:', COLOR_GREEN)}\n{deeplinks_formatted}")
        else:
            results.append(f"{colorize_text('[!] No deep links found.', COLOR_YELLOW)}")

        urls, ip_addresses = analyzer.extract_urls()
        if urls:
            urls_formatted = "\n".join(urls)
            results.append(f"\n{colorize_text('[+] URLs Found:', COLOR_GREEN)}\n{urls_formatted}")
        else:
            results.append(f"\n{colorize_text('[!] No URLs found.', COLOR_YELLOW)}")

        if ip_addresses:
            ips_formatted = "\n".join(ip_addresses)
            results.append(f"\n{colorize_text('[+] IP Addresses Found:', COLOR_GREEN)}\n{ips_formatted}")
        else:
            results.append(f"\n{colorize_text('[!] No IP addresses found.', COLOR_YELLOW)}")

        final_result = "\n".join(results)
        print(colorize_text(final_result, COLOR_WHITE))
        self.add_report_section("Additional Information (Deep Links, URLs, IPs)", final_result)

    def test_cryptography(self):
        logging.info(colorize_text("Testing for Insufficient Cryptography (checking plaintext secrets in prefs)...", COLOR_YELLOW))
        # Defining search patterns
        search_patterns = 'key|secret|password|token|auth|api'


        commands = [

            f'''adb shell "su 0 sh -c 'grep -E --color=always -i \\"{search_patterns}\\" /data/data/{self.package_name}/shared_prefs/*.xml'"''',
            f'''adb shell run-as {self.package_name} grep -E -i "{search_patterns}" /data/data/{self.package_name}/shared_prefs/*.xml'''
        ]

        grep_output = ""
        success = False

        for cmd in commands:
            try:

                logging.debug(f"Executing command: {cmd}")

                # Execute the command
                grep_output = subprocess.check_output(
                    cmd,
                    shell=True,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                success = True
                break
            except subprocess.CalledProcessError as e:

                logging.warning(f"Command failed: {cmd}")
                logging.debug(f"Error Output: {e.output.strip()}")
                continue

        if success and grep_output:
            print(grep_output)

            sanitized_output = re.sub(r'\x1b\[[0-9;]*m', '', grep_output)


            result = f"{colorize_text('[!] Potential plaintext keys or secrets found:', COLOR_RED)}\n{sanitized_output}"
        elif success and not grep_output.strip():
            # No matches found; print success message in green
            success_message = '[+] No plaintext keys or secrets found in shared_prefs.'
            print(colorize_text(success_message, COLOR_GREEN))
            result = f"{colorize_text(success_message, COLOR_GREEN)}"
        else:

            error_output = e.output.strip() if 'e' in locals() else "Unknown error occurred."
            error_message = f"[!] Failed to access shared_prefs or no secrets found: {error_output}"
            print(colorize_text(error_message, COLOR_RED))
            result = f"{colorize_text('[!] Failed to access shared_prefs or no secrets found:', COLOR_RED)} {error_output}"


        self.add_report_section("Insufficient Cryptography (M5)", result)


    # Debuggable & Logging Checks
    def test_debuggable_logging(self):
        logging.info(colorize_text("Testing for Debuggable & Logging Issues...", COLOR_YELLOW))
        # Checking if the app is debuggable
        output = self.drozer.run_command(f"run app.package.info -a {self.package_name}")
        if "debuggable=true" in output:
            result = f"{colorize_text('[!] App is debuggable. Risky for production.', COLOR_RED)}"
        else:
            result = f"{colorize_text('[+] App is not debuggable.', COLOR_GREEN)}"

        print(colorize_text(result, COLOR_WHITE))
        self.add_report_section("Debuggable and Logging Checks", result)


    def generate_report(self):
        logging.info(colorize_text("Generating Report...", COLOR_YELLOW))
        with open("report.md", "w", encoding="utf-8") as report:
            report.write("# OWASP Mobile Top 10 Security Report\n\n")
            report.write("This report contains the findings from the automated OWASP Mobile Top 10 security tests.\n\n")

            for section_title, section_data in self.report_data:
                report.write(f"## {section_title}\n")
                report.write(section_data + "\n\n")

        logging.info(colorize_text("Report generated at 'report.md'.", COLOR_CYAN))

    def full_test_suite(self):
        print_banner()
        self.start_drozer()

        if not self.check_drozer_connection():
            logging.error("Drozer connection not available. Exiting.")
            return


        run_logcat_monitor(self.package_name)

        self.unpack_apk()
        self.improper_platform_usage()
        self.attack_surface_analysis()
        self.insecure_data_storage()
        self.traversal_vulnerabilities()
        self.injection_vulnerabilities()
        self.extract_additional_info()
        self.test_cryptography()
        self.test_debuggable_logging()
        self.generate_report()

def ensure_drozer_agent_ready():
    package_name = "com.mwr.dz"
    agent_apk_path = os.path.join("tools", "drozer-agent.apk")

    logging.info("Checking if Drozer agent is installed on device...")

    try:
        result = subprocess.check_output(["adb", "shell", "pm", "list", "packages", package_name], text=True)
        if package_name not in result:
            logging.warning(colorize_text("Drozer agent not installed. Attempting to install...", COLOR_YELLOW))

            if not os.path.exists(agent_apk_path):
                logging.error(colorize_text(f"Could not find drozer-agent.apk at {agent_apk_path}", COLOR_RED))
                sys.exit(1)

            install_result = subprocess.run(["adb", "install", agent_apk_path], capture_output=True, text=True)
            if "Success" in install_result.stdout:
                logging.info(colorize_text("Drozer agent installed successfully.", COLOR_GREEN))
            else:
                logging.error(colorize_text(f"Drozer agent installation failed:\n{install_result.stdout}\n{install_result.stderr}", COLOR_RED))
                sys.exit(1)
        else:
            logging.info(colorize_text("Drozer agent is already installed.", COLOR_GREEN))

        # Check if agent is running
        logging.info("Checking if Drozer agent is currently running...")
        ps_output = subprocess.check_output(["adb", "shell", "ps"], text=True)

        if "com.mwr.dz" in ps_output:
            logging.info(colorize_text("Drozer agent is already running.", COLOR_GREEN))
        else:
            logging.warning(colorize_text("Drozer agent is not running. Starting it now...", COLOR_YELLOW))
            # Launch agent via monkey tool
            subprocess.run([
                "adb", "shell", "monkey", "-p", "com.mwr.dz", "-c",
                "android.intent.category.LAUNCHER", "1"
            ], check=True)
            logging.info(colorize_text("Drozer agent launched.", COLOR_GREEN))
            # Allow some buffer time for startup
            time.sleep(2)

    except subprocess.CalledProcessError as e:
        logging.error(colorize_text(f"Error checking or launching Drozer agent: {e}", COLOR_RED))
        sys.exit(1)

# Parameters - Manually provide the APK path and package name.
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="Path to APK file")
    parser.add_argument("--package", help="Package name")
    args = parser.parse_args()

    # Ensure drozer agent is on device
    ensure_drozer_agent_ready()

    if args.apk:
        apk_path = args.apk
    else:
        apk_path = input("Enter path to APK file: ") # E.g "/home/kali/Desktop/APKs/35.5.4.apk"

    if args.package:
        package_name = args.package
    else:
        package_name = input("Enter package name: ") # "com.zhiliaoapp.musically"

    suite = OWASPTestSuiteDrozer(apk_path, package_name)
    suite.full_test_suite()
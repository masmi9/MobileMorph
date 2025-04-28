import os
import sys
import subprocess
import re
from utils import paths, file_utils, logger
import xml.etree.ElementTree as ET

### This will use apktool, jadx, semgrep, strings, and some regex to hunt for exported components WebView configs, weak crypto, etc.

def is_semgrep_docker_running():
    """Check if Semgrep Docker container is running."""
    try:
        # Run `docker ps` to check for the Semgrep container
        result = subprocess.run(["docker", "ps", "--filter", "ancestor=returntocorp/semgrep", "--format", "{{.Names}}"], capture_output=True, text=True)
        # If any container is running with the 'returntocorp/semgrep' image, it will return its name.
        if result.stdout.strip():
            logger.info("Semgrep Docker container is already running.")
            return True
        else:
            logger.info("Semgrep Docker container is not running.")
            return False
    except subprocess.CalledProcessError as e:
        logger.warning(f"Error checking Docker container status: {e}")
        return False

def start_semgrep_docker_container():
    """Start the Semgrep Docker container if it's not running."""
    try:
        logger.info("Starting Semgrep Docker container...")
        subprocess.run(["docker", "run", "-d", "--name", "semgrep", "-v", f"{os.getcwd()}:/mnt", "returntocorp/semgrep"], check=True)
        logger.info("Semgrep Docker container started.")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Error starting Semgrep Docker container: {e}")

def get_apktool_cmd():
    # adjust this if needed - or make configurable
    apktool_path = "apktool"
    if os.name == "nt": #Windows
        apktool_path = r"C:\Users\MalikSmith\apktool\apktool.bat"
    return apktool_path

def decompile_apk(apk_path, output_dir):
    logger.info(f"Decompiling {apk_path} with apktool...")
    subprocess.run([get_apktool_cmd(), "d", "-f", apk_path, "-o", output_dir])

def extract_strings(apk_path, output_file):
    logger.info(f"Extracting strings from {apk_path}...")
    with open(output_file, "w") as out:
        subprocess.run(["strings", apk_path], stdout=out)

def extract_permissions(manifest_path):
    try:
        # Parse the AndroidManifest.xml file
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        # Define the namespace to handle XML namespaces correctly
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        # Find all <uses-permission> tags
        permissions = root.findall('.//uses-permission')
        # Extract the name of each permission
        permission_list = [perm.attrib['{http://schemas.android.com/apk/res/android}name'] for perm in permissions]

        # Define a list of dangerous permissions
        dangerous_permissions = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_PHONE_STATE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.AUTHENTICATE_ACCOUNTS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.CAMERA"
        ]
        
        # Identify and report dangerous permissions
        dangerous_found = [perm for perm in permission_list if perm in dangerous_permissions]
        if dangerous_found:
            logger.warning("Dangerous permissions found in AndroidManifest.xml:")
            for perm in dangerous_found:
                print(f" - {perm}")
        else:
            logger.info("No dangerous permissions found.")
        
        return permission_list
    except Exception as e:
        print(f"Error parsing manifest for permissions: {e}")
        return []

def scan_manifest(manifest_path):
    logger.info(f"Scanning AndroidManifest.xml for exported components...")
    with open(manifest_path, "r") as manifest:
        content = manifest.read()
        #Step 1: Regex to capture all components with android:exported="true"
        exported = re.findall(r'<(activity|service|receiver)[^>]*android:exported="true"[^>]*android:name="([^"]+)"', content)
        # Print the number of exported components found
        logger.logtext(f"Exported components found: {len(exported)}")
        if exported:
            for match in exported:
                component_type = match[0]
                component_name = match[1]
                logger.logtext(f"Exported {component_type} component found: {component_name}")
        else:
            logger.logtext("No exported components found.")
        
        #Step 2: Extract and print permissions from the manifest
        permissions = extract_permissions(manifest_path)
        if permissions:
            logger.info("Permissions Declared in AndroidManifest.xml:")
            for perm in permissions:
                print(f" - {perm}")
            else:
                logger.info("No permissions found in AndroidManifest.xml")

def scan_smali_code(smali_dir):
    logger.info("Scanning smali files for potential dangerous code...")
    # Define smali patterns to look for in code (e.g., dangerous API calls)
    dangerous_patterns = [
        r'Ljava/net/URL;-><init>\(Ljava/lang/String;\)',
        r'Ljava/lang/Runtime;->exec\(Ljava/lang/String;\)',
        r'android/net/Uri;->parse\(Ljava/lang/String;\)',
        # Add more patterns here...
    ]
    # Loop through all smali files in the directory
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Check for any dangerous patterns
                    for pattern in dangerous_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            logger.logtext(f"Found dangerous pattern in {file_path}: {matches}")

def scan_decompiled_code(java_dir):
    logger.info("Scanning Java files for potentially dangerous code...")
    # Define the semgrep command with the pattern to scan for risky code (like risky function calls, hardcoded credentials)
    semgrep_cmd = ["docker", "run", "--rm", "-v", f"{os.getcwd()}:/mnt", "returntocorp/semgrep", "semgrep", "--config", "auto", "/mnt"]
    try:
        subprocess.run(semgrep_cmd, check=True)
    except subprocess.CalledProcessError as e:
        logger.warning(f"Error running Semgrep: {e}")

def run_static_analysis(apk_path):
    downloads_folder = paths.get_output_folder()
    base_name = os.path.basename(apk_path).replace(".apk", "")
    output_dir = os.path.join(downloads_folder, f"{base_name}_decompiled")
    strings_file = os.path.join(downloads_folder, f"{base_name}_strings.txt")
    manifest_path = f"{output_dir}/AndroidManifest.xml"

    # Check if Semgrep Docker container is running, if not, start it
    if not is_semgrep_docker_running():
        start_semgrep_docker_container()
    
    # Decompile APK file
    decompile_apk(apk_path, output_dir)
    extract_strings(apk_path, strings_file)
    
    if os.path.exists(manifest_path):
        scan_manifest(manifest_path)
    else:
        logger.warning("AndroidManifest.xml not found after decompilation.")

    # Scan the decompiled code (smali or Java)
    smali_dir = os.path.join(output_dir, 'smali')
    java_dir = os.path.join(output_dir, 'src')

    if os.path.exists(smali_dir):
        scan_smali_code(smali_dir)
    elif os.path.exists(java_dir):
        scan_decompiled_code(java_dir)
    else:
        logger.warning("No smali or Java code found after decompilation.")

if __name__ == "__main__":
    run_static_analysis(sys.argv[1])
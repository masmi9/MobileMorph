import os
import subprocess
import re
from utils import paths, file_utils, logger

### This will use apktool, jadx, strings, and some regex to hunt for exported components WebView configs, weak crypto, etc.

def get_apktool_cmd():
    # adjust this if needed - or make configurable
    apktool_path = "apktool"
    if os.name == "nt": #Windows
        apktool_path = r"C:\Users\MalikSmith\apktool\apktool.bat"
    return apktool_path

def decompile_apk(apk_path, output_dir):
    print(f"[+] Decompiling {apk_path} with apktool...")
    subprocess.run([get_apktool_cmd(), "d", "-f", apk_path, "-o", output_dir])

def extract_strings(apk_path, output_file):
    print(f"[+] Extracting strings from {apk_path}...")
    with open(output_file, "w") as out:
        subprocess.run(["strings", apk_path], stdout=out)

def scan_manifest(manifest_path):
    print(f"[+] Scanning AndroidManifest.xml for exported components...")
    with open(manifest_path, "r") as manifest:
        content = manifest.read()
        exported = re.findall(r'android:exported="true"', content)
        print(f"[*] Exported components found: {len(exported)}")
        for match in exported:
            print(match)

def apk_static_analysis(apk_path):
    downloads_folder = paths.get_output_folder()
    base_name = os.path.basename(apk_path).replace(".apk", "")
    output_dir = os.path.join(downloads_folder, f"{base_name}_decompiled")
    strings_file = os.path.join(downloads_folder, f"{base_name}_strings.txt")
    manifest_path = f"{output_dir}/AndroidManifest.xml"
    
    decompile_apk(apk_path, output_dir)
    extract_strings(apk_path, strings_file)
    
    if os.path.exists(manifest_path):
        scan_manifest(manifest_path)
    else:
        logger.warning("[!] AndroidManifest.xml not found after decompilation.")

if __name__ == "__main__":
    import sys
    apk_static_analysis(sys.argv[1])
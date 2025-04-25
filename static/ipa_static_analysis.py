import os
import subprocess
import plistlib
import zipfile
from utils import paths

### Unpacks an .ipa, extracts Info.plist, runs strings on binary, checks for URL schemes, insecure ATS settings.

def unzip_ipa(ipa_path, output_dir):
    print(f"[+] Unzipping {ipa_path}...")
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(output_dir)

def extract_strings(binary_path, output_file):
    print(f"[+] Extracting strings from {binary_path}...")
    with open(output_file, "w") as out:
        subprocess.run(["strings", binary_path], stdout=out)

def parse_info_plist(plist_path):
    print(f"[+] Parsing Info.plist...")
    with open(plist_path, 'rb') as f:
        plist_data = plistlib.load(f)
        url_schemes = plist_data.get('CFBundleURLTypes', [])
        ats_settings = plist_data.get('NSAppTransportSecurity', {})
        
        print(f"[*] URL Schemes: {url_schemes}")
        print(f"[*] ATS Settings: {ats_settings}")

def ipa_static_analysis(ipa_path):
    downloads_folder = paths.get_output_folder()
    base_name = os.path.basename(ipa_path).replace(".ipa", "")
    output_dir = os.path.join(downloads_folder, f"{base_name}_unzipped")
    unzip_ipa(ipa_path, output_dir)
    
    payload_dir = os.path.join(output_dir, "Payload")
    app_dirs = [d for d in os.listdir(payload_dir) if d.endswith(".app")]

    if app_dirs:
        app_path = os.path.join(payload_dir, app_dirs[0])
        plist_path = os.path.join(app_path, "Info.plist")
        binary_path = os.path.join(app_path, app_dirs[0].split('.app')[0])

        extract_strings(binary_path, f"output/{base_name}_strings.txt")
        parse_info_plist(plist_path)
    else:
        print("[!] No .app directory found inside Payload.")

if __name__ == "__main__":
    import sys
    ipa_static_analysis(sys.argv[1])

import os
import sys
import subprocess
import re
from utils import paths, logger
import plistlib
import zipfile
from threat_intel.ti_scanner import scan_indicators

def unzip_ipa(ipa_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(output_dir)

def find_info_plist(root_dir):
    """Locate the Info.plist file."""
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file == "Info.plist":
                return os.path.join(root, file)
    return None

def scan_info_plist(plist_path):
    logger.info(f"Scanning Info.plist for interesting settings...")
    try:
        with open(plist_path, 'rb') as f:
            plist_data = plistlib.load(f)
        
        if plist_data.get('NSAppTransportSecurity', {}).get('NSAllowsArbitraryLoads', False):
            logger.warning("Insecure App Transport Security (ATS) - NSAllowsArbitraryLoads enabled.")

        if 'UIWebView' in str(plist_data):
            logger.warning("Deprecated UIWebView usage detected.")

        if plist_data.get('LSApplicationQueriesSchemes'):
            logger.logtext("App declares custom URL schemes: Potential privacy leakage.")
            for scheme in plist_data['LSApplicationQueriesSchemes']:
                print(f"  - {scheme}")

    except Exception as e:
        logger.warning(f"Error parsing Info.plist: {e}")

def scan_source_code(root_dir):
    """Scan Objective-C and Swift source files for dangerous patterns."""
    print("[+] Scanning source code files (.m, .swift)...")
    patterns = {
        "Hardcoded Credentials": r'\"[A-Za-z0-9\-_]{10,}\"',  # Any suspicious string constants
        "HTTP URLs": r'http://[^\s"\']+',
        "Weak Crypto (MD5)": r'CC_MD5',
        "Dynamic Loading": r'NSClassFromString|objc_msgSend',
        "URL Loading": r'NSURL\s*\*|NSURLRequest',
    }

    findings = []
    ioc_candidates = []

    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(('.m', '.swift')):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for issue, regex in patterns.items():
                            matches = re.findall(regex, content)
                            if matches:
                                findings.append((issue, filepath, matches))
                        ioc_candidates.extend(re.findall(r'http[s]?://[^\s"\']+', content))
                except Exception as e:
                    print(f"[!] Error reading {filepath}: {e}")

    for issue, filepath, matches in findings:
        print(f"[!] {issue} detected in {filepath}: {len(matches)} occurrence(s)")
    
    return findings, list(set(ioc_candidates))

def scan_for_jailbreak_detection(root_dir):
    """Scan for jailbreak detection logic inside extracted IPA contents."""
    logger.info("Scanning source code for jailbreak detection logic...")
    jailbreak_indicators = [
        "Cydia.app",
        "MobileSubstrate.dylib",
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/",
        "fork",
        "ptrace",
        "jailbreak",
        r'\broot\b'
    ]
    findings = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(('.m', '.swift', '.plist', '.json', '.txt')):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for indicator in jailbreak_indicators:
                            if re.search(indicator, content):
                                findings.append((filepath, indicator))
                except Exception as e:
                    logger.warning(f"Error reading {filepath}: {e}")
    if findings:
        logger.warning("Potential Jailbreak Detection Code Found:")
        for filepath, indicator in findings:
            logger.logtext(f" - {indicator} found in {filepath}")
    else:
        logger.info("No jailbreak detection indicators found in source code.")

def run_static_analysis(ipa_path):
    logger.info(f"Starting IPA static analysis for {ipa_path}...")
    downloads_folder = paths.get_output_folder()
    base_name = os.path.basename(ipa_path).replace(".ipa", "")
    output_dir = os.path.join(downloads_folder, f"{base_name}_extracted")
    
    # Unzip the IPA
    unzip_ipa(ipa_path, output_dir)

    # Locate Info.plist
    plist_path = find_info_plist(output_dir)
    if plist_path:
        scan_info_plist(plist_path)
    else:
        logger.warning("Info.plist not found")

    # Collect findings + IOC indicators
    findings, ioc_candidates = scan_source_code(output_dir)

    # Scan indicators against threat intelligence feeds
    scan_indicators(ioc_candidates, source_file=ipa_path)

    # Scan for jailbreak detection
    scan_for_jailbreak_detection(output_dir)

    logger.info("Static analysis for IPA completed.")

if __name__ == "__main__":
    run_static_analysis(sys.argv[1])

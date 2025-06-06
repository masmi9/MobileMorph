import os
import sys
import subprocess
import re
import requests
import logging
from utils import paths, logger
import xml.etree.ElementTree as ET
import static.secrets_scanner as secrets
from cve_scanner.scanner import scan_gradle_file_for_cves
from dashboard.progress_tracker import update_progress
from threat_intel.ti_scanner import scan_indicators
from utils.threat_score_utils import calculate_risk_score
from static.manifest_inspector import APKAnalyzer

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
    apk_name = os.path.basename(apk_path).replace(".apk", "")
    script_path = os.path.join(os.getcwd(), "tools", "apk_to_java.sh")

    # Use default output dir based on APK name if not provided
    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), f"{apk_name}_output")

    logger.info(f"Running apk_to_java.sh on {apk_path}...")

    try:
        subprocess.run([script_path, apk_path], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to decompile APK: {e}")
        return None

    java_dir = os.path.join(output_dir, "java")
    if not os.path.isdir(java_dir):
        logger.warning(f"Decompiled Java directory not found at: {java_dir}")
        return None

    logger.info(f"Java source extracted to: {java_dir}")
    return java_dir

def advanced_data_flow(smali_dir):
    logger.info("Performing data flow analysis...")
    sources = [r'getIntent', r'getExtras', r'getStringExtra']
    sinks = [r'Runtime\.exec', r'loadUrl', r'eval']
    method_flows = {}
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                path = os.path.join(root, file)
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.readlines()
                    current_method = None
                    has_source = False
                    has_sink = False
                    for line in content:
                        if line.strip().startswith('.method'):
                            current_method = line.strip()
                            has_source = has_sink = False
                        if any(src in line for src in sources):
                            has_source = True
                        if any(src in line for src in sinks):
                            has_sink = True
                        if line.strip().startswith('.end method') and current_method:
                            if has_source and has_sink:
                                method_flows.setdefault(path, []).append(current_method)
                            current_method = None
    if method_flows:
        logger.warning("Potential source-to-sink flows detected:")
        for file_path, methods in method_flows.items():
            for method in methods:
                logger.logtext(f" - File: {file_path}, Method: {method}")
    else:
        logger.info("No direct source-to-sink method level flows detected.")

def audit_third_party_libraries(apk_path):
    logger.info("Auditing third-party libraries and versions...")
    try:
        output = subprocess.check_output(["aapt", "dump", "badging", apk_path], text=True)
        libraries = {}
        version_code = None
        version_name = None
        for line in output.splitlines():
            if line.startswith("package:"):
                version_code_match = re.search(r"versionCode='(\d+)'", line)
                version_name_match = re.search(r"versionName='([^']+)'", line)
                if version_code_match:
                    version_code = version_code_match.group(1)
                if version_name_match:
                    version_name = version_name_match.group(1)
            if line.startswith("uses-package:"):
                pkg = re.search(r"name='([^']+)'", line)
                if pkg:
                    libraries[pkg.group(1)] = "unknown"
        logger.logtext(f"Third-party libraries detected: {libraries}")
        logger.logtext(f"App versionCode: {version_code}, versionName: {version_name}")

        # Real-time CVE check with OSS Index
        # Map Android package names to Maven coordinates
        for lib, ver in libraries.items():
            if ver == "unknown":
                logger.warning(f"No version for {lib}, skipping CVE check.")
                continue
            # Construct Package URL - assuming Maven coordinates (Java/Android)
            coordinate = f"pkg:maven/{lib}/{ver}"
            logger.info(f"Querying OSS Index for {coordinate}...")
            ossindex_url = "https://ossindex.sonatype.org/api/v3/component-report"
            payload = {"coordinates": [coordinate]}
            response = requests.post(ossindex_url, json=payload)
            
            if response.status_code == 200:
                results = response.json()
                if results:
                    vulns = results[0].get("vulnerabilities", [])
                    if vulns:
                        logger.warning(f"{lib} version {ver} has {len(vulns)} vulnerabilities:")
                        for vuln in vulns:
                            logger.logtext(f" - {vuln['id']}: {vuln['title']} (CVSS {vuln.get('cvssScore', 'N/A')})")
                    else:
                        logger.info(f"No known vulnerabilities for {lib} version {ver}.")
                else:
                    logger.info("No results returned from OSS Index.")
            else:
                logger.info(f"OSS Index query failed for {coordinate} with status {response.status_code}.")

    except Exception as e:
        logger.warning(f"Failed to audit third-party libraries: {e}")

def extract_strings(apk_path, output_file):
    logger.info(f"Extracting strings from {apk_path}...")
    with open(output_file, "w") as out:
        subprocess.run(["strings", apk_path], stdout=out)

def extract_permissions(manifest_path):
    try:
        # Parse the AndroidManifest.xml file
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        # Extract the name of each permission
        permission_list = [perm.attrib['{http://schemas.android.com/apk/res/android}name'] for perm in root.findall('.//uses-permission')]
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
    
    # Run manifest and component analysis
    analyzer = APKAnalyzer(manifest_path, verbose=False, quiet=True, cleanup=True)
    results = analyzer.analyze()

    if 'error' in results:
        logger.error(f"Manifest scan failed: {results['error']}")
        return {
            "exported_components": [],
            "icc_risks": [],
            "raw_results": {}
        }

    exported_components = []
    icc_risks = []

    components = results.get('components', {})
    for comp_type, comp_list in components.items():
        for comp in comp_list:
            name = comp.get("name")
            permission = comp.get("permission")
            exported_components.append((comp_type, name))

            if permission is None and comp_type in ['activity', 'service', 'receiver']:
                icc_risks.append((comp_type, name))

    # Log the findings
    for comp_type, comp_name in exported_components:
        logger.logtext(f"Exported {comp_type}: {comp_name}")

    if icc_risks:
        logger.warning("Exported components missing protection (no android:permission):")
        for comp_type, comp_name in icc_risks:
            logger.logtext(f" - {comp_type}: {comp_name}")
    else:
        logger.info("No obvious ICC permission risks found.")

    # Return full results for reporting
    return {
        "exported_components": exported_components,
        "icc_risks": icc_risks,
        "raw_results": results
    }

def scan_network_security_config(output_dir):
    """Looks for res/xml/network_security_config.xml or manifest flags."""
    config_path = os.path.join(output_dir, "res", "xml", "network_security_config.xml")
    manifest_path = os.path.join(output_dir, "AndroidManifest.xml")

    if os.path.exists(config_path):
        with open(config_path, "r") as config:
            content = config.read()
            if "<trust-anchors>" in content:
                logger.warning("Custom trust anchors found in network security config.")
            if "cleartextTrafficPermitted" in content:
                logger.warning("Cleartext traffic may be allowed by network_security_config.xml.")
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as manifest:
            if "android:usesCleartextTraffic=\"true\"" in manifest.read():
                logger.warning("Cleartext traffic explicitly allowed in Manifest.")

def scan_smali_code(smali_dir):
    logger.info("Scanning smali files for potential dangerous code...")
    # Define smali patterns to look for in code (e.g., dangerous API calls)
    dangerous_patterns = [
        r'Ljava/net/URL;-><init>\(Ljava/lang/String;\)',
        r'Ljava/lang/Runtime;->exec\(Ljava/lang/String;\)',
        r'android/net/Uri;->parse\(Ljava/lang/String;\)',
        r'MD5|SHA1|SHA-1|SHA256|AES/ECB|DES',
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

def scan_for_root_detection(smali_dir):
    logger.info("Scanning smali files for root detection logic...")
    root_detection_indicators = [
        "isDeviceRooted",
        "checkRoot",
        "checkSuBinary",
        "/system/app/Superuser.apk",
        "com.noshufou.android.su",
        "eu.chainfire.supersu",
        "magisk",
        r'\bsu\b'
    ]
    found_indicators = []
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for indicator in root_detection_indicators:
                        if re.search(indicator, content):
                            found_indicators.append((file_path, indicator))
    if found_indicators:
        logger.warning("Potential Root Detection Code Found:")
        for file_path, indicator in found_indicators:
            logger.logtext(f" - {indicator} found in {file_path}")
    else:
        logger.info("No root detection indicators found in the smali code.")

def scan_decompiled_code(java_dir):
    logger.info("Scanning Java files for potentially dangerous code...")
    # Get absolute path to ensure Docker volume mount works
    abs_path = os.path.abspath(java_dir)
    if not os.path.isdir(abs_path):
        logger.warning(f"Invalid Java directory for Semgrep: {abs_path}")
        return
    # Define the semgrep command with the pattern to scan for risky code (like risky function calls, hardcoded credentials)
    semgrep_cmd = ["docker", "run", "--rm", "-v", f"{abs_path}:/mnt", "returntocorp/semgrep", "semgrep", "--config", "p/owasp-mobile", "/mnt"]
    try:
        subprocess.run(semgrep_cmd, check=True)
        logger.info("Semgrep scan completed.")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Error running Semgrep: {e}")

def scan_decompiled_code_with_findings(java_dir):
    findings = []
    tainted_vars = set()
    for root, _, files in os.walk(java_dir):
        for file in files:
            if file.endswith(".java"):
                filepath = os.path.join(root, file)
                relpath = os.path.relpath(filepath, java_dir)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        for i, line in enumerate(lines):
                            line_number = i + 1
                            combined_line = line
                            if i + 1 < len(lines):
                                combined_line += lines[i +1]
                            # Runtime.exec detection
                            if re.search(r'\bRuntime\.getRuntime\(\)\.exec\s*\(', combined_line):
                                findings.append({
                                    "type": "command_execution",
                                    "message": "Use of Runtime.exec() usage",
                                    "file": relpath,
                                    "line": line_number
                                })
                            # SSH client library usage (e.g., JSch)
                            if re.search(r'\bJSch\b|\bSession\b|setPortForwardingL|setPassword', line):
                                findings.append({
                                    "type": "ssh_config",
                                    "message": "Possible SSH client/tunneling configuration (e.g., JSch)",
                                    "file": relpath,
                                    "line": line_number
                                })
                            # SSH commands in exec (e.g., Runtime.getRuntime().exec("ssh ..."))
                            if "ssh" in line and re.search(r'Runtime\.getRuntime\(\)\.exec\s*\(', combined_line):
                                findings.append({
                                    "type": "ssh_command_exec",
                                    "message": "Hardcoded SSH command found in Runtime.exec()",
                                    "file": relpath,
                                    "line": line_number
                                })
                            # Embedded SSH key indicators
                            if re.search(r'BEGIN (RSA|DSA|EC) PRIVATE KEY|\.pem', line):
                                findings.append({
                                    "type": "embedded_ssh_key",
                                    "message": "Possible embedded SSH private key or PEM file",
                                    "file": relpath,
                                    "line": line_number
                                })
                            # WebView.loadURL
                            if re.search(r'\.loadUrls\s*\(', combined_line):
                                findings.append({
                                    "type": "webview_usage",
                                    "message": "Potential unsafe WebView.loadUrl() usage",
                                    "file": relpath,
                                    "line": line_number
                                })
                            # Suspicious URL hardcoding (attacker.com, localhost, etc.)
                            if re.search(r'"(http|https|ftp)://[^"]*(attacker|localhost|127\.|192\.168|shell\.jsp)', line, re.IGNORECASE):
                                findings.append({
                                    "type": "suspicious_url",
                                    "message": "Suspicious hardcoded URL or shell path",
                                    "file": relpath,
                                    "line": line_number
                                })
                            # URL instantiation (possible SSRF)
                            if re.search(r'new\s+URL\s*\(', combined_line):
                                findings.append({
                                    "type": "ssrf_potential",
                                    "message": "URL object instantiated; check for tainted input",
                                    "file": relpath,
                                    "line": line_number
                                })
                            # Base64 decoding (common in obfuscation or C2 behavior)
                            if re.search(r'Base64\.decode|Base64Decoder', line):
                                findings.append({
                                    "type": "base64_decode",
                                    "message": "Base64 decoding detected (possible obfuscation)",
                                    "file": relpath,
                                    "line": line_number
                                })
                            # Reflection
                            if re.search(r'Class\.forName|Method\.invoke|Field\.setAccessible', line):
                                findings.append({
                                    "type": "reflection_usage",
                                    "message": "Reflection API usage detected",
                                    "file": relpath,
                                    "line": line_number
                                })
                            # Taint source detection (user input methods)
                            taint_match = re.search(r'String\s+(\w+)\s*=\s*.*(getIntent|getExtras|getStringExtra|getData)\s*\(', line)
                            if taint_match:
                                tainted_vars.add(taint_match.group(1))
                            # Tainted data used in dangerous sink
                            if any(var in line for var in tainted_vars) and re.search(r'exec|loadUrl|openConnection', line):
                                findings.append({
                                    "type": "tainted_data_usage",
                                    "message": f"Tainted variable used in sensitive context: {line.strip()}",
                                    "file": relpath,
                                    "line": line_number
                                })
                            
                except Exception as e:
                    print(f"[!] Error reading {filepath}: {e}")
    return findings

def scan_webview_usage(smali_dir):
    logger.info("Scanning for risky WebView configurations...")
    webview_issues = []
    webview_patterns = [
        r'setJavaScriptEnabled\s*\(\s*true\s*\)',
        r'addJavascriptInterface',
        r'setWebViewClient'
    ]
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern in webview_patterns:
                        if re.search(pattern, content):
                            msg = f"'{pattern}' found in {file_path}"
                            logger.warning(f"Risky WebView config '{pattern}' found in {file_path}")
                            webview_issues.append(msg)
    return webview_issues

def scan_code_complexity(smali_dir):
    logger.info("Calculating code complexity metrics...")
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                path = os.path.join(root, file)
                method_count = 0
                branch_count = 0
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if line.strip().startswith('.method'):
                            method_count += 1
                        if any(branch in line for branch in ['if-', 'switch', 'goto']):
                            branch_count += 1
                if method_count > 20 or branch_count > 50:
                    logger.warning(
                        f"High complexity: {method_count} methods and {branch_count} branches in {path}")

def detect_hardcoded_keys(smali_dir):
    logger.info("Scanning for hardcoded crypto keys / secrets...")
    key_patterns = [
        r'([A-Fa-f0-9]{32,})',  # Hex strings (typical for keys)
        r'key\s*=\s*[\"\'][^\"\'\s]{8,}[\"\'\s]',  # Simple "key=" assignment
        r'secret\s*=\s*[\"\'][^\"\'\s]{8,}[\"\'\s]',
        r'iv\s*=\s*[\"\'][^\"\'\s]{8,}[\"\'\s]'
    ]
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern in key_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            logger.warning(f"Potential hardcoded keys in {file_path}: {matches}")
    
def detect_reflection_usage(smali_dir):
    logger.info("Scanning for reflection usage...")
    patterns = [r'Class\.forName', r'Method\.invoke', r'getDeclaredMethod', r'getDeclaredField']
    findings = []
    for root_dir, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                path = os.path.join(root_dir, file)
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern in patterns:
                        if re.search(pattern, content):
                             msg = f"Reflection pattern '{pattern}' found in {path}"
                             logger.logtext(f"Reflection pattern '{pattern}' found in {path}")
                             findings.append(msg)
    return findings

def detect_obfuscation(smali_dir):
    logger.info("Scanning for obfuscation heuristics...")
    obfuscated_files = 0
    total_files = 0
    for root_dir, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                total_files += 1
                rel_path = os.path.relpath(os.path.join(root_dir, file), smali_dir)
                if re.search(r'/[a-z]{1,2}/[a-z]{1,2}/[a-z]{1,2}\.smali$', rel_path):
                    obfuscated_files += 1
                    logger.logtext(f"Obfuscated-looking file: {file}")
    if total_files > 0:
        percent = (obfuscated_files/total_files) * 100
        logger.info(f"Obfuscated files: {obfuscated_files}/{total_files} ({percent:.2f}%)")

def run_static_analysis(apk_path, file_id=None):
    downloads_folder = paths.get_output_folder()
    base_name = os.path.basename(apk_path).replace(".apk", "")
    output_dir = os.path.join(downloads_folder, f"{base_name}_decompiled")
    strings_file = os.path.join(downloads_folder, f"{base_name}_strings.txt")
    manifest_path = f"{output_dir}/AndroidManifest.xml"

    results = {
        "exported_components":[],
        "webview_config": [],
        "hardcoded_keys": [],
        "secrets": [],
    }

    update_progress(file_id, 10)
    # Check if Semgrep Docker container is running, if not, start it
    if not is_semgrep_docker_running():
        start_semgrep_docker_container()
    
    update_progress(file_id, 20)
    # Decompile APK file
    decompile_apk(apk_path, output_dir)
    extract_strings(apk_path, strings_file)

    # CVE scan from build.gradle
    build_gradle_path = os.path.join(output_dir, "app", "build.gradle")
    if os.path.exists(build_gradle_path):
        logger.info("Found build.gradle, starting CVE scan...")
        update_progress(file_id, 30)
        cve_results = scan_gradle_file_for_cves(build_gradle_path)
        results["cve_scan_results"] = cve_results
    else:
        logger.warning("No build.gradle found for CVE scanning.")
    
    update_progress(file_id, 40)
    if os.path.exists(manifest_path):
        results["permissions"] = extract_permissions(manifest_path)
        # Perform component analysis
        manifest_scan = scan_manifest(apk_path)
        results["exported_components"] = manifest_scan["exported_components"]
        results["icc_risks"] = manifest_scan["icc_risks"]
        results["adb_exploits"] = manifest_scan["raw_results"].get("exploits", [])
        scan_network_security_config(output_dir)
    else:
        logger.warning("AndroidManifest.xml not found after decompilation.")

    update_progress(file_id, 55)
    # Scan the decompiled code (smali or Java)
    smali_dir = os.path.join(output_dir, 'smali')
    java_dir = os.path.join(output_dir, 'src')

    if os.path.exists(smali_dir):
        scan_smali_code(smali_dir)
        # Capture root detection indicators
        root_indicators = []
        root_detection_indicators = [
            "isDeviceRooted", "checkRoot", "checkSuBinary",
            "/system/app/Superuser.apk", "com.noshufou.android.su",
            "eu.chainfire.supersu", "magisk", r'\bsu\b'
        ]
        for root, _, files in os.walk(smali_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for indicator in root_detection_indicators:
                            if re.search(indicator, content):
                                root_indicators.append(f"{indicator} found in {file_path}")
        if root_indicators:
            logger.warning("Potential Root Detection Code Found:")
            for line in root_indicators:
                logger.logtext(f" - {line}")
        else:
            logger.info("No root detection indicators found.")
        # Store root findings in results
        results["root_detection"] = root_indicators
        update_progress(file_id, 70)
        results["reflection_usage"] = detect_reflection_usage(smali_dir)
        detect_obfuscation(smali_dir)
        advanced_data_flow(smali_dir)
        detect_hardcoded_keys(smali_dir)
        # Check for embedded SSH private keys in strings
        ssh_key_indicators = []
        try:
            with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if "BEGIN RSA PRIVATE KEY" in line or ".pem" in line:
                        ssh_key_indicators.append(f"Possible embedded SSH key in line {i + 1}: {line.strip()}")
        except Exception as e:
            logger.warning(f"Error checking for SSH keys: {e}")
        results["ssh_keys"] = ssh_key_indicators
        results["webview_config"] = scan_webview_usage(smali_dir)
        scan_code_complexity(smali_dir)
    elif os.path.exists(java_dir):
        # scan_decompiled_code(java_dir)
        results["static_findings"] = scan_decompiled_code_with_findings(java_dir)
    else:
        logger.warning("No smali or Java code found after decompilation.")

    update_progress(file_id, 85)
    if os.path.exists(strings_file):
        secrets_result = secrets.scan_for_secrets(strings_file)
        results["secrets"] = secrets_result
        if secrets_result:
            logger.warning("Potential secrets detected in strings extraction.")
            for name, match in secrets_result:
                logger.logtext(f" - {name}: {match}")
    # IOC Detection + Threat Enrichment
    ioc_candidates = []
    try:
        with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            ioc_candidates = re.findall(r'(?:https?|ftp)://[^\s\'"]+', content)
            ioc_candidates += re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
            ioc_candidates = list(set(ioc_candidates))
            results["ioc_candidates"] = ioc_candidates
    except Exception as e:
        logger.warning(f"Failed to extract IOC candidates from strings: {e}")
    scan_indicators(ioc_candidates, source_file=apk_path)
    
    audit_third_party_libraries(apk_path)
    update_progress(file_id, 95)
    results["ioc_candidates"] = list(set(ioc_candidates))

    results = calculate_risk_score(results)
    return base_name, results

if __name__ == "__main__":
    run_static_analysis(sys.argv[1])
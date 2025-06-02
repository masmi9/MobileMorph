import argparse
import sys
import os
import subprocess
# Add static analysis paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'static'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'dynamic'))
# Import your analysis modules
import static.apk_static_analysis as apk
import static.ipa_static_analysis as ipa
import static.secrets_scanner as secrets
from utils.paths import get_output_folder 
from utils import logger, frida_helpers
from report import report_generator
import exploits.exploit_runner as exp
from utils.emulator_manager import ensure_emulator_ready
from report.report_generator import ReportGenerator
from dashboard.models import ScanResult, db
import json

analysis_results = {}

def perform_static_analysis(args):
    global analysis_results
    downloads_folder = get_output_folder()
    findings = {}

    if args.apk:
        base_name, results = apk.run_static_analysis(args.apk)
        exported_components = results.get("exported_components", [])
        webview_components = results.get("webview_config", [])
        strings_file = os.path.join(downloads_folder, f"{os.path.basename(args.apk).replace('.apk', '')}_strings.txt")
        secrets_result = secrets.scan_for_secrets(strings_file)

        findings = {
            "Secrets Scan Results": secrets_result,
            "Static Analysis Logs": f"Decompiled APK and strings dumped at {strings_file}"
        }
        report = ReportGenerator(base_name, downloads_folder, mode="static")
        report.generate_static_report(findings=findings)

        # Save the results globally for exploit to use later
        analysis_results = results

        # Save APK static findings to dashboard DB
        scan = ScanResult (
            filename = os.path.basename(args.apk),
            platform = "apk",
            scan_type = "static",
            findings = json.dumps(findings)
        )
        db.session.add(scan)
        db.session.commit()

        # Write findings to static JSON file for download
        report_path = os.path.join("dashboard", "static", "reports")
        os.makedirs(report_path, exist_ok=True)
        with open(os.path.join(report_path, f"{base_name}_findings.json"), "w") as f:
            json.dump(results, f, indent=2)


    elif args.ipa:
        base_name = ipa.run_static_analysis(args.ipa)
        strings_file = f"output/{os.path.basename(args.ipa).replace('.ipa', '')}_strings.txt"
        secrets_result = secrets.scan_for_secrets(strings_file)

        findings = {
            "Secrets Scan Results": secrets_result,
            "Static Analysis Logs": f"Decompiled IPA and strings dumped at {strings_file}"
        }
        report = ReportGenerator(base_name, downloads_folder, mode="static")
        report.generate_static_report(findings=findings)

        # Save IPA static findings to dashboard DB
        scan = ScanResult (
            filename = os.path.basename(args.ipa),
            platform = "ipa",
            scan_type = "static",
            findings = json.dumps(findings)
        )
        db.session.add(scan)
        db.session.commit()

        # Write findings to static JSON file for download
        report_path = os.path.join("dashboard", "static", "reports")
        os.makedirs(report_path, exist_ok=True)
        with open(os.path.join(report_path, f"{base_name}_findings.json"), "w") as f:
            json.dump(results, f, indent=2)
    
    else:
        logger.warning("Please specify either --apk or --ipa for static analysis.")

def device_connected():
    """Check if any Android device/emulator is connected."""
    try:
        output = subprocess.check_output(["adb", "devices"], text=True)
        lines = [line for line in output.strip().splitlines() if "\tdevice" in line]
        return len(lines) > 0
    except Exception:
        return False

def run_dynamic_analysis(args, selected_profile="minimal"):
    if not frida_helpers.FRIDA_AVAILABLE:
        logger.error("Frida is not available or failed to import. Dynamic analysis cannot proceed.")
        return

    if args.setup_emulator:
        logger.logtext("Setting up emulator before starting dynamic analysis...")
        ensure_emulator_ready(args.apk)   # Corrected: pass apk path
    else:
        if not device_connected():
            logger.error("No Android device/emulator detected. Use --setup-emulator or connect a device manually.")
            return
    
    if args.apk:
        logger.info("Launching dyna.py for dynamic analysis...")
        # Dynamically extract the package name from APK
        package_name = get_package_name_from_apk(args.apk)
        if not package_name:
            logger.error("Could not extract package name from APK Aborting dynamic analysis.")
            return
        try:
            subprocess.run(["python", "dyna.py" , "--apk", args.apk, "--package", package_name], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Dynamic analysis failed: {e}")
        # Inject specific Frida script if --frida-script is provided
        #if args.frida_script:
        #    frida_script_path = os.path.join("dynamic", "frida_hooks", args.frida_script)
        #    if os.path.exists(frida_script_path):
        #        engine.inject_frida_script(frida_script_path)
        #    else:
        #        logger.warning(f"Frida script not found at {frida_script_path}")
        #engine.start()
    elif args.ipa:
        logger.logtext("Dynamic analysis for IPA is not yet supported. Please provide an IPA.")
    else:
        logger.warning("Please specify either --apk or --ipa for dynamic analysis.")

def get_package_name_from_apk(apk_path):
    try:
        output = subprocess.check_output(["aapt", "dump", "badging", apk_path], text=True)
        for line in output.splitlines():
            if line.startswith("package:"):
                parts = line.split()
                for part in parts:
                    if part.startswith("name="):
                        package_name = part.split("=")[1].replace("'", "")
                        logger.info(f"Extracted package name: {package_name}")
                        return package_name
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to extract package name: {e}")
    return None

def run_exploit(args):
    downloads_folder = get_output_folder()

    if args.apk:
        package_name = get_package_name_from_apk(args.apk)

        if not package_name:
            logger.error("Failed to extract package name from APK.")
            return

        # This assumes static analysis already dumped strings
        strings_file = os.path.join(downloads_folder, f"{os.path.basename(args.apk).replace('.apk', '')}_strings.txt")

        if not os.path.exists(strings_file):
            logger.warning(f"Strings file not found: {strings_file}. Run static analysis first.")
            strings_file = ""  # Still allow run_exploit to proceed without credentials check

        exported_components = analysis_results.get("exported_components", [])
        webview_components = analysis_results.get("webview_config", [])
        exp.run_exploit(package_name, strings_file, exported_components, webview_components)

    elif args.ipa:
        logger.warning("Exploitation for IPA is not implemented yet.")
    else:
        logger.warning("Please specify either --apk or --ipa for exploitation.")

def run_agent(args):
    logger.info("Starting MobileMorph Agent deployment...")

    # Optional: build agent
    os.chdir("android-agent")
    subprocess.run(["./gradlew", "assembleDebug"])
    os.chdir("..")

    agent_apk_path = os.path.join("android-agent", "build", "outputs", "apk", "debug", "android-agent-debug.apk")

    if not os.path.exists(agent_apk_path):
        logger.error("Agent APK build failed.")
        return

    # Install agent APK on the connected device
    subprocess.run(["adb", "install", "-r", agent_apk_path])

    # Start MainService or main activity
    subprocess.run(["adb", "shell", "am", "startservice", "com.example.agent/.MainService"])

    logger.success("Agent deployed and service started.")

    # Optionally start the Flask server
    if args.server:
        logger.logtext("Launching MobileMorph Agent server...")
        subprocess.Popen(["python", "server/app.py"])

def run_report(args):
    downloads_folder = get_output_folder()
    if args.apk:
        base_name = os.path.basename(args.apk).replace(".apk", "")
    elif args.ipa:
        base_name = os.path.basename(args.ipa).replace(".ipa", "")
    else:
        logger.error("You must specify either --apk or --ipa to generate a report.")
        sys.exit(1)
    
    if args.static:
        report_mode = "static"
    elif args.dynamic:
        report_mode = "dynamic"
    elif args.exploit:
        report_mode = "exploit"
    elif args.agent:
        report_mode = "agent"
    else:
        report_mode = "static" # Default
    report = ReportGenerator(base_name, downloads_folder, mode=report_mode, findings=analysis_results)
    report.generate_static_report()

def main():
    parser = argparse.ArgumentParser(description="MobileMorph - Mobile Pentesting Framework")
    parser.add_argument('--static', action='store_true', help='Run static analysis')
    parser.add_argument('--dynamic', action='store_true', help='Run dynamic analysis')
    parser.add_argument('--exploit', action='store_true', help='Perform vulnerability exploitation')
    parser.add_argument('--report', action='store_true', help='Generate a professional report')
    parser.add_argument('--apk', type=str, help='Path to APK file')
    parser.add_argument('--ipa', type=str, help='Path to IPA file')
    parser.add_argument("--package", type=str, help="Package name")
    parser.add_argument('--profile', type=str, default='minimal', help='Frida hook profile for dynamic analysis (default: minimal, full, ssl_only, crypto_focus, stealth)')
    parser.add_argument('--frida-script', type=str, help="Optional: custom Frida script to inject from dynamic frida hooks")
    parser.add_argument('--proxy', action='store_true', help='Force app traffic through proxy via Frida hooks')
    parser.add_argument('--setup-emulator', action='store_true', help='Prepare emulator with Frida snapshot')
    parser.add_argument('--agent', action='store_true', help='Deploy or interact with MobileMorph Agent')
    parser.add_argument('--server', action='store_true', help='Launch agent C2 server')
    parser.add_argument('--ui', action='store_true', help='Launch MobileMorph dashboard UI')
    args = parser.parse_args()

    if args.static:
        perform_static_analysis(args)
    if args.dynamic:
        # ProxyMode overrides profile
        selected_profile = "proxy" if args.proxy else args.profile
        run_dynamic_analysis(args, selected_profile)
    if args.exploit:
        run_exploit(args)
    if args.report:
        run_report(args)
    if args.agent:
        run_agent(args)
    # Only run setup-emulator directly if --dynamic is NOT specified
    if args.setup_emulator and not args.dynamic:
        ensure_emulator_ready(args.apk)
        sys.exit(0)
    if args.ui:
        from dashboard.app import create_app
        app = create_app()
        app.run(debug=True, port=5050)
        return # Prevent rest of main() from executing after UI is launched
    if not frida_helpers.FRIDA_AVAILABLE and (args.dynamic or args.exploit):
        logger.warning("Frida is not available. Dynamic analysis and exploitation will be skipped.")

if __name__ == "__main__":
    main()

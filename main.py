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
from dynamic.dynamic_runner import DynamicAnalysisEngine, start_dynamic_analysis, get_package_name_from_apk
import exploits.exploit_runner as exp
from utils.emulator_manager import ensure_emulator_ready
from report.report_generator import ReportGenerator
from static.apk_static_analysis import get_exported_components, get_webview_components

def run_static_analysis(args):
    downloads_folder = get_output_folder()
    findings = {}

    if args.apk:
        base_name = apk.run_static_analysis(args.apk)
        strings_file = os.path.join(downloads_folder, f"{os.path.basename(args.apk).replace('.apk', '')}_strings.txt")
        secrets_result = secrets.scan_for_secrets(strings_file)

        findings = {
            "Secrets Scan Results": secrets_result,
            "Static Analysis Logs": f"Decompiled APK and strings dumped at {strings_file}"
        }
        report = ReportGenerator(base_name, downloads_folder, mode="static")
        report.generate_static_report(findings=findings)

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
        engine = DynamicAnalysisEngine(args.apk, hook_profile=selected_profile)
        engine.start()
    elif args.ipa:
        logger.logtext("Dynamic analysis for IPA is not yet supported. Please provide an IPA.")
    else:
        logger.warning("Please specify either --apk or --ipa for dynamic analysis.")

def run_exploit(args):
    downloads_folder = get_output_folder()

    if args.apk:
        package_name = get_package_name_from_apk(args.apk)

        if not package_name:
            logger.error("Failed to extract package name from APK.")
            return

        # This assumes static analysis already dumped strings
        strings_file = os.path.join(downloads_folder, f"{os.path.basename(args.apk).replace('.apk', '')}_strings.txt")

        # Extract exported components and WebView components
        exported_components = get_exported_components(args.apk)
        webview_components = get_webview_components(args.apk)

        if not os.path.exists(strings_file):
            logger.warning(f"Strings file not found: {strings_file}. Run static analysis first.")
            strings_file = ""  # Still allow run_exploit to proceed without credentials check

        exp.run_exploit(package_name, strings_file, exported_components, webview_components)

    elif args.ipa:
        logger.warning("Exploitation for IPA is not implemented yet.")
    else:
        logger.warning("Please specify either --apk or --ipa for exploitation.")


def run_report(args):
    downloads_folder = get_output_folder()
    if args.apk:
        base_name = os.path.basename(args.apk).replace(".apk", "")
    elif args.ipa:
        base_name = os.path.basename(args.ipa).replace(".ipa", "")
    else:
        logger.error("You must specify either --apk or --ipa to generate a report.")
        sys.exit(1)
    # You can optionally pass findings=None here if you want simpler mode
    report_generator.generate_report(base_name, "full", findings=None)

def main():
    parser = argparse.ArgumentParser(description="MobileMorph - Mobile Pentesting Framework")
    parser.add_argument('--static', action='store_true', help='Run static analysis')
    parser.add_argument('--dynamic', action='store_true', help='Run dynamic analysis')
    parser.add_argument('--exploit', action='store_true', help='Perform vulnerability exploitation')
    parser.add_argument('--report', action='store_true', help='Generate a professional report')
    parser.add_argument('--apk', type=str, help='Path to APK file')
    parser.add_argument('--ipa', type=str, help='Path to IPA file')
    parser.add_argument('--profile', type=str, default='minimal', help='Frida hook profile for dynamic analysis (default: minimal, full, ssl_only, crypto_focus, stealth)')
    parser.add_argument('--proxy', action='store_true', help='Force app traffic through proxy via Frida hooks')
    parser.add_argument('--setup-emulator', action='store_true', help='Prepare emulator with Frida snapshot')
    args = parser.parse_args()

    if args.static:
        run_static_analysis(args)
    if args.dynamic:
        # ProxyMode overrides profile
        selected_profile = "proxy" if args.proxy else args.profile
        run_dynamic_analysis(args, selected_profile)
    if args.exploit:
        run_exploit(args)
    if args.report:
        run_report(args)
    # Only run setup-emulator directly if --dynamic is NOT specified
    if args.setup_emulator and not args.dynamic:
        ensure_emulator_ready(args.apk)
        sys.exit(0)
    if not frida_helpers.FRIDA_AVAILABLE and (args.dynamic or args.exploit):
        logger.warning("Frida is not available. Dynamic analysis and exploitation will be skipped.")

if __name__ == "__main__":
    main()

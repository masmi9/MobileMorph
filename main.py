import argparse
import sys
import os
# Add static analysis paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'static'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'dynamic'))
# Import your analysis modules
import static.apk_static_analysis as apk
import static.ipa_static_analysis as ipa
import static.secrets_scanner as secrets
from utils.paths import get_output_folder 
from utils import logger
from report import report_generator
from dynamic.dynamic_runner import DynamicAnalysisEngine, start_dynamic_analysis
import exploits.exploit_runner as exp
from utils.emulator_manager import ensure_emulator_ready

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
        report_generator.generate_report(base_name, "static", findings)
    
    elif args.ipa:
        base_name = ipa.run_static_analysis(args.ipa)
        strings_file = f"output/{os.path.basename(args.ipa).replace('.ipa', '')}_strings.txt"
        secrets_result = secrets.scan_for_secrets(strings_file)

        findings = {
            "Secrets Scan Results": secrets_result,
            "Static Analysis Logs": f"Decompiled IPA and strings dumped at {strings_file}"
        }
        report_generator.generate_report(base_name, "static", findings)
    
    else:
        logger.warning("Please specify either --apk or --ipa for static analysis.")

def run_dynamic_analysis(args):
    if args.apk:
        engine = DynamicAnalysisEngine(args.apk, hook_profile=args.profile)
        engine.start()
    elif args.ipa:
        logger.logtext("Dynamic analysis for IPA is not yet supported. Please provide an IPA.")
    else:
        logger.warning("Please specify either --apk or --ipa for dynamic analysis.")

def run_exploit(args):
    if args.apk:
        exp.exploit_apk(args.apk)
    elif args.ipa:
        exp.exploit_ipa(args.ipa)
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
    parser.add_argument('--profile', type=str, default='minimal', help='Frida hook profile for dynamic analysis')
    parser.add_argument('--setup-emulator', action='store_true', help='Prepare emulator with Frida snapshot')
    args = parser.parse_args()

    if args.static:
        run_static_analysis(args)
    if args.dynamic:
        run_dynamic_analysis(args)
    if args.exploit:
        run_exploit(args)
    if args.report:
        run_report(args)
    if args.setup_emulator:
        ensure_emulator_ready()
        sys.exit(0)

if __name__ == "__main__":
    main()

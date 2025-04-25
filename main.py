import argparse
import sys
import os
# Add static analysis paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'static'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'dynamic'))
# Import your analysis modules
import static.apk_static_analysis
import static.ipa_static_analysis
import static.secrets_scanner
from utils.paths import get_output_folder
from report import report_generator
from dynamic.dynamic_runner import DynamicAnalysisEngine, start_dynamic_analysis
import argparse

def run_static_analysis(args):
    downloads_folder = get_output_folder()
    findings = {}
    if args.apk:
        base_name = static.apk_static_analysis.apk_static_analysis(args.apk)
        strings_file = os.path.join(downloads_folder, f"{os.path.basename(args.apk).replace('.apk', '')}_strings.txt")
        secrets_result = static.secrets_scanner.scan_for_secrets(strings_file)

        findings = {
            "Secrets Scan Results": secrets_result,
            "Static Analysis Logs": f"Decompiled APK and strings dumped at {strings_file}"
        }

        report_generator.generate_report(base_name, "static", findings)
    elif args.ipa:
        base_name = static.ipa_static_analysis.ipa_static_analysis(args.ipa)
        strings_file = f"output/{os.path.basename(args.ipa).replace('.ipa', '')}_strings.txt"
        secrets_result = static.secrets_scanner.scan_for_secrets(strings_file)

        findings = {
            "Secrets Scan Results": secrets_result,
            "Static Analysis Logs": f"Decompiled IPA and strings dumped at {strings_file}"
        }
        report_generator.generate_report(base_name, "static", findings)
    else:
        print("[!] Please specify either --apk or --ipa for static analysis.")

def run_dynamic_analysis(args):
    if args.apk:
        engine = DynamicAnalysisEngine(args.apk)
        engine.start()
    elif args.ipa:
        print("[*] Dynamic analysis for IPA is not yet supported. Please provide an APK.")
    else:
        print("[!] Please specify either --apk or --ipa for dynamic analysis.")

def main():
    parser = argparse.ArgumentParser(description="MobileMorph - Mobile Pentesting Framework")

    parser.add_argument('--static', action='store_true', help='Run static analysis')
    parser.add_argument('--dynamic', action='store_true', help='Run dynamic analysis (coming soon)')
    parser.add_argument('--apk', type=str, help='Path to APK file')
    parser.add_argument('--ipa', type=str, help='Path to IPA file')
    parser.add_argument('--report', action='store_true', help='Generate report (coming soon)')

    args = parser.parse_args()

    if args.static:
        run_static_analysis(args)
    elif args.dynamic:
        run_dynamic_analysis(args)
    elif args.report:
        print("[*] Report generation not implemented yet.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

import os
from datetime import datetime
from utils import paths, file_utils, logger

def generate_report(app_name, analysis_type, findings):
    downloads_folder = paths.get_output_folder()
    reports_folder = os.path.join(downloads_folder, "Reports")
    file_utils.ensure_dir(reports_folder)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(reports_folder, f"{app_name}_{analysis_type}_report_{timestamp}.txt")

    with open(report_file, 'w') as f:
        f.write("=====================================\n")
        f.write(f"MobileMorph Analysis Report\n")
        f.write("=====================================\n")
        f.write(f"App Name: {app_name}\n")
        f.write(f"Analysis Type: {analysis_type}\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        f.write("=====================================\n")
        f.write("Findings Summary\n")
        f.write("=====================================\n")

        if not findings:
            f.write("No findings detected.\n")
        else:
            for section_title, section_content in findings.items():
                f.write(f"\n--- {section_title} ---\n")
                f.write(f"{section_content}\n")

    logger.info(f"[+] Report saved to {report_file}")
    return report_file

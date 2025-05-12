import os
import datetime
from utils import logger

class ReportGenerator:
    def __init__(self, app_name, output_dir, mode="static", findings=None):
        self.app_name = app_name
        self.output_dir = output_dir
        self.mode = mode
        self.findings = findings or {}
        self.report_file = os.path.join(output_dir, f"{datetime.datetime.now().strftime('%Y%m%d_%H%M')}_{app_name}_report.md")

    def generate_static_report(self, findings=None):
        logger.info("Generating static analysis report...")
        manifest_results = os.path.join(self.output_dir, f"{self.app_name}_manifest_results.txt")
        strings_results = os.path.join(self.output_dir, f"{self.app_name}_strings.txt")

        with open(self.report_file, "w") as report:
            report.write(f"# Static Analysis Report for {self.app_name}\n\n")

            # Write findings summary if available
            if findings:
                report.write("## Findings Summary\n\n")
                for key, value in self.findings.items():
                    report.write(f"**{key}**:\n{value}\n\n")
                                 
            if os.path.exists(manifest_results):
                report.write("## Exported Components & Permissions\n\n")
                with open(manifest_results, "r") as f:
                    report.write(f.read())
            else:
                report.write("- No manifest results found.\n\n")

            if os.path.exists(strings_results):
                report.write("## Interesting Strings\n\n")
                with open(strings_results, "r") as f:
                    report.write(f.read())
            else:
                report.write("- No extracted strings found.\n\n")

    def generate_agent_report(self):
        logger.info("Generating MobileMorph Agent C2 report...")
        agent_log_path = os.path.join(self.output_dir, f"{self.app_name}_agent_c2_log.txt")

        with open(self.report_file, "w") as report:
            report.write(f"# MobileMorph Agent C2 Report for {self.app_name}\n\n")
            if os.path.exists(agent_log_path):
                report.write("## Command-and-Control Log\n\n")
                with open(agent_log_path, "r") as f:
                    report.write(f.read())
            else:
                report.write("- No agent C2 logs found.\n\n")

    def generate_dynamic_report(self):
        logger.info("Generating dynamic analysis report...")
        traffic_log = os.path.join(self.output_dir, f"{self.app_name}_traffic_log.txt")

        with open(self.report_file, "w") as report:
            report.write(f"# Dynamic Analysis Report for {self.app_name}\n\n")

            if os.path.exists(traffic_log):
                report.write("## Intercepted HTTP/S Traffic\n\n")
                with open(traffic_log, "r") as f:
                    report.write(f.read())
            else:
                report.write("- No traffic logs captured.\n\n")

    def generate_exploit_report(self):
        logger.info("Generating exploit findings report...")
        exploit_results = os.path.join(self.output_dir, f"{self.app_name}_exploit_results.txt")

        with open(self.report_file, "w") as report:
            report.write(f"# Exploitation Results for {self.app_name}\n\n")

            if os.path.exists(exploit_results):
                report.write("## Successful Findings\n\n")
                with open(exploit_results, "r") as f:
                    report.write(f.read())
            else:
                report.write("- No exploitation findings found.\n\n")

    def generate_report(self):
        if self.mode == "static":
            self.generate_static_report()
        elif self.mode == "dynamic":
            self.generate_dynamic_report()
        elif self.mode == "exploit":
            self.generate_exploit_report()
        elif self.mode == "agent":
            self.generate_agent_report()
        else:
            logger.error(f"Unknown report mode: {self.mode}")

        logger.success(f"Report generated: {self.report_file}")
        return self.report_file
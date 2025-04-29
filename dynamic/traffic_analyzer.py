import re
import os
from utils import logger

class TrafficAnalyzer:
    def __init__(self, traffic_log_path):
        self.traffic_log_path = traffic_log_path
        self.sensitive_patterns = [
            ("API Key", re.compile(r'(?i)(api[_-]?key\s*[=:]\s*\"?[A-Za-z0-9-_]{16,}\"?)')),
            ("Authorization Bearer", re.compile(r'(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9-_\.]+')),
            ("Basic Auth", re.compile(r'(?i)authorization\s*:\s*basic\s+[A-Za-z0-9=\+/]+')),
            ("JWT Token", re.compile(r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*')),
            ("Access Token", re.compile(r'(?i)(access[_-]?token\s*[=:]\s*\"?[A-Za-z0-9-_]{16,}\"?)')),
            ("Client Secret", re.compile(r'(?i)(client[_-]?secret\s*[=:]\s*\"?[A-Za-z0-9-_]{8,}\"?)')),
            ("Session Cookie", re.compile(r'(?i)set-cookie:.*?session.*?\b')),
            ("Private Key", re.compile(r'-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----', re.DOTALL)),
        ]

    def analyze(self):
        if not os.path.exists(self.traffic_log_path):
            logger.error(f"Traffic log not found: {self.traffic_log_path}")
            return []

        findings = []

        with open(self.traffic_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            traffic_data = f.read()

        for label, pattern in self.sensitive_patterns:
            matches = pattern.findall(traffic_data)
            if matches:
                for match in matches:
                    findings.append((label, match if isinstance(match, str) else match[0]))

        if findings:
            logger.success(f"[+] {len(findings)} potential sensitive artifacts found!")
        else:
            logger.info("[*] No sensitive data patterns detected in captured traffic.")

        return findings

    def save_findings(self, output_file):
        findings = self.analyze()
        if not findings:
            return

        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            for label, value in findings:
                f.write(f"[{label}] {value}\n")

        logger.success(f"[+] Findings saved to {output_file}")

# Example usage
if __name__ == "__main__":
    analyzer = TrafficAnalyzer("output/traffic_logs/sample_traffic.txt")
    analyzer.analyze()

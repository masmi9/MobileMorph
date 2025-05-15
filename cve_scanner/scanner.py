import os
import re
import json
from cve_scanner.osv_utils import query_osv_for_package
from utils import logger

def extract_maven_dependencies(build_gradle_path):
    """Very simple regex-based extractor for Maven dependencies from build.gradle."""
    deps = []
    with open(build_gradle_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = re.match(r'implementation\s+[\'"]([\w\.-]+):([\w\.-]+):([\w\.-]+)[\'"]', line.strip())
            if match:
                group, name, version = match.groups()
                full_name = f"{group}.{name}"
                deps.append((full_name, version))
    return deps

def scan_gradle_file_for_cves(build_gradle_path):
    logger.info(f"Scanning {build_gradle_path} for CVEs using osv.dev")
    deps = extract_maven_dependencies(build_gradle_path)
    results = {}

    for name, version in deps:
        logger.logtext(f"Querying CVEs for: {name}:{version}")
        osv_response = query_osv_for_package(name, version, ecosystem="Maven")
        if osv_response.get("vulns"):
            results[f"{name}:{version}"] = osv_response["vulns"]
        else:
            results[f"{name}:{version}"] = []

    return results

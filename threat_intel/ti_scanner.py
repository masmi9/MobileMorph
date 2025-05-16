import json
import os
import re
import requests
from utils import logger

VT_API_KEY = os.environ.get("VT_API_KEY")  # Set via environment variable

INDICATOR_LOG = os.path.join("threat_intel", "indicators.json")

def scan_indicators(indicators, source_file="unknown"):
    if not indicators:
        logger.info("No indicators to scan.")
        return

    logger.info(f"Scanning {len(indicators)} indicator(s) via threat intelligence APIs...")

    results = []
    for item in indicators:
        result = {
            "indicator": item,
            "source": source_file,
            "virustotal": None,
            "threat_score": 0
        }

        # Basic VirusTotal scan if key is present
        if VT_API_KEY:
            domain = extract_domain(item)
            try:
                headers = {"x-apikey": VT_API_KEY}
                resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
                if resp.ok:
                    data = resp.json()
                    result["virustotal"] = data["data"]["attributes"].get("last_analysis_stats", {})
                    result["threat_score"] = data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
            except Exception as e:
                logger.warning(f"VirusTotal error on {item}: {e}")

        results.append(result)

    # Log to indicators.json
    os.makedirs(os.path.dirname(INDICATOR_LOG), exist_ok=True)

    old_data = []
    if os.path.exists(INDICATOR_LOG):
        try:
            with open(INDICATOR_LOG, "r") as f:
                content = f.read().strip()
                if content:
                    old_data = json.loads(content)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning(f"Could not parse exisiting indicator log: {e}. Overwriting.")

    old_data.extend(results)
    with open(INDICATOR_LOG, "w") as f:
        json.dump(old_data, f, indent=2)

    logger.info(f"IOC scan completed. Logged to {INDICATOR_LOG}")

def extract_domain(url):
    try:
        return re.search(r"https?://([^/]+)", url).group(1)
    except:
        return url

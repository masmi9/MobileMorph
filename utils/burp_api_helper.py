import requests
import subprocess
import os
from utils import logger

BURP_API_URL = "http://localhost:1337/v0.1"  # Adjust if using different port or API
BURP_API_KEY = "u27cIvA8QAzktVI51olstuMr1r43Bazl"
BURP_PATH = "C:\Users\MalikSmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Burp Suite Pro\Burp Suite Professional.lnk"

def start_burp():
    logger.info("Starting BurpSuite in headless mode...")
    try:
        # Adjust this path to where your Burp executable is
        subprocess.Popen([BURP_PATH, "--headless", "--api-key", BURP_API_KEY])
    except Exception as e:
        logger.warning(f"[!] Could not auto-start Burp: {e}. Please ensure Burp is running manually.")

def send_url_to_burp(url):
    headers = {"Authorization": BURP_API_KEY} if BURP_API_KEY else {}
    try:
        response = requests.post(
            f"{BURP_API_URL}/scan",
            json={"url": url},
            headers=headers,
            timeout=10
        )
        if response.ok:
            logger.info(f"[+] URL sent to Burp Scanner: {url}")
        else:
            logger.error(f"[-] Failed to send URL to Burp: {url} | Status: {response.status_code} | Response: {response.text}")
    except Exception as e:
        logger.error(f"[!] Exception sending URL to Burp: {e}")



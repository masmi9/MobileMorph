![MobileMorph png](https://github.com/user-attachments/assets/52233bb6-c5c1-48d8-b633-baa118f651a9)
# MobileMorph - Automated Mobile App Pentesting Framework

**MobileMorph** is a modular and extensible mobile application security testing framework designed to automate **static**, **dynamic**, and **exploit-based** analysis for Android and iOS applications. It integrates advanced features such as Frida-based instrumentation, emulator automation, BurpSuite integration, runtime file/traffic inspection, and C2 agent deployment to empower offensive security engineers and mobile red teamers.

---

## Features

### Static Analysis
- APK/IPA decompilation using `jadx` / `class-dump`
- Secrets scanning (`API keys`, `JWTs`, `passwords`) in extracted strings
- Permission and component enumeration
- AndroidManifest/Info.plist analysis
- Permission and component enumeration
- Taint flow tracking from input to sink (basic & advanced)
- WebView misconfiguration detection
- Obfuscation heuristics and reflection usage
- CVE matching for third-party libraries using OSS Index

### Dynamic Analysis
- Automated APK installation and app launch
- Frida-based runtime hooking:
  - Use `--profile full` or `--profile minimal` to control which hooks are injected
  - Available hooks:  
    - `bypass_ssl.js`: Bypass SSL pinning
    - `hook_crypto.js`: Hook cryptographic APIs
    - `network_logger.js`: Log URL and network usage
    - `auth_bypass.js`: Force login and bypass authentication
    - `root_bypass.js`: Defeat root/jailbreak detection
- Traffic interception:
  - Android: `traffic_interceptor.py`
  - iOS: `traffic_interceptor_ios.py`
- Logcat monitoring for credential/session/token leaks
- Filesystem monitoring for insecure storage (SharedPreferences, plaintext tokens, DBs)
- **BurpSuite Integration**:
  - Auto-submits runtime-discoverd URLs for active scanning
  - Supports Burp headless mode and API-driven scans

### Exploitation Toolkit
- Exported component abuse and WebView injection
- Basic IDOR replay and role tampering
- Token reuse/login bypass fuzzing
- Exploit runner integration with APKs post-analysis

### MobileMorph Agent (C2)
- Custom Android agent for command injection and payload execution
- C2 server built with FastAPI(`server/app.py`)
- Agent Capabilities:
  - `run_shell`, `list_files`, `read_file`, `write_file`, `load_jar`, `uninstall`
  - Dynamic `agent_id` generation from device
  - Persistence using `BOOT_COMPLETED` receiver
  - DexClassLoader-based dynamic payload loading

### Emulator Automation
- Headless emulator provisioning via `--setup-emulator`
- Provisioned rooted emulator with Frida preloaded
- Auto-snapshot (`frida_ready`) for instant reuse in future runs

---

## Project Structure

```plaintext
MobileMorph/
├── main.py
├── static/
│   ├── apk_static_analysis.py
│   ├── ipa_static_analysis.py                  # (1) iOS Static Support
│   └── secrets_scanner.py
├── dynamic/
│   ├── dynamic_runner.py
│   ├── frida_hooks/
│   │   ├── bypass_jailbreak.js                 # (1) iOS Hook
│   │   ├── get-security-provider.js
│   │   ├── hook_keychain.js                    # (1) iOS Hook
│   │   ├── hook_allmethods.js
│   │   ├── hook_targetmethods.js
│   │   ├── intent_hook.js
│   │   ├── network_logger.js
│   │   ├── proxy_force.js
│   │   ├── webview-allmethods.js
│   │   └── webview-targetmethods.js                 
│   ├── traffic_interceptor.py
│   ├── traffic_interceptor_ios.py              # (1) iOS Dynamic Support
│   ├── hook_loader.py
│   ├── traffic_analyzer.py
│   ├── mitm/
│   │   ├── modify_requests.py
│   ├── modules/
│   │   ├── logcat_monitor.py
│   │   └── storage_monitor.py
├── exploits/
│   └── exploit_runner.py
├── agent-app/
│   ├── agent_payloads/
│   ├── android-agent/
│   ├── native_injector/
│   └── server/
├── report/
│   └── report_generator.py
├── threat_intel/                                # (2) IOC + Threat Feed Module
│   ├── ti_scanner.py
│   └── indicators.json
├── dashboard/                                   # (3) Web UI
│   ├── app.py
│   ├── routes.py
│   ├── models.py
│   └── templates/
│       ├── index.html
│       ├── results.html
│       └── upload.html
├── cve_scanner/                                 # (4) Dependency CVE Detection
│   ├── scanner.py
│   └── osv_utils.py
├── utils/
│   ├── burp_api_helper.py                       # (5) Extended for custom Burp plugin/log bridge
│   ├── emulator_manager.py
│   ├── file_utils.py
│   ├── frida_helpers.py
│   ├── logger.py
│   └── paths.py
├── README.md
└── requirements.txt
```

## Usage
### Static Analysis
```bash
python3 main.py --apk path/to/app.apk --static
```
### Dynamic Analysis with Frida
```bash
python3 main.py --apk path/to/app.apk --dynamic
```
### Dynamic Analysis with Custom Frida Hook Profile
```bash
python3 main.py --apk path/to/app.apk --dynamic --profile full
```
  - Avaible profiles: minimal(default), full, ssl_only, crypto_focus, stealth 
### Exploitation (after dynamic)
```bash
python3 main.py --apk path/to/app.apk --exploit
```
### Agent Deployment + C2 Server
```bash
python3 main.py --apk path/to/app.apk --agent --server
```
### Run All Analyses (Static + Dynamic + Exploit)
```bash
python3 main.py --apk path/to/app.apk --static --dynamic --exploit
```
### Emulator Setup with Snapshot (Frida-Ready)
```bash
python3 main.py --setup-emulator
```

## Attack Surface Coverage
- Insecure data storage (SharedPreferences, SQLite, local files)
- Insecure communication (HTTP, broken SSL pinning)
- Root detection & bypass (hooked via Frida)
- WebView abuse and file:// URI injection
- IDOR & replay token-based privilege escalation
- Runtime secrets/log/token leakage via Logcat
- Malicious paylaod injection (via agent or Frida)
- CVE exposure in embedded libraries

## Requirements
- Python 3.8+
- Android SDK + ADB
- Frida CLI (pip install frida-tools)
- jadx, aapt, ideviceinstaller, frida-server (for mobile runtime hooks)
- Ensure ANDROID_HOME or ANDROID_SDK_ROOT is properly configured

## Install dependencies:
```bash
pip install -r requirements.txt
```

##⚙️ Roadmap
- iOS dynamic support (experimental -- alpha)
- Expand Burp automation to support passive scanning and reporting import
- Integration with MobSF or Drozer-like module system
- Add signature bypass via runtime patching
- Passive BurpSuite scan support
- Remote Frida hook injection over USB/IP



👨‍💻 Author
Malik Smith
Built with ❤️ for advanced mobile app pentesting automation as well as serious mobile security research and red teaming.

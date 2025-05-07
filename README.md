# MobileMorph - Automated Mobile App Pentesting Framework

**MobileMorph** is a modular and extensible security testing framework built to automate static and dynamic analysis of Android and iOS applications. It integrates Frida hooks, traffic interception, filesystem monitoring, and secrets detection to uncover critical mobile app vulnerabilities during runtime and build time.

---

## Features

### Static Analysis
- APK/IPA decompilation using `jadx` / `class-dump`
- Secrets scanning (`API keys`, `JWTs`, `passwords`) in extracted strings
- Permission and component enumeration
- Manifest/Info.plist analysis

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
  - Automatically sends discovered URLs to Burp Scanner
  - Supports scanning multiple unique URLs found at runtime
  - Can optionally auto-start BurpSuite in headless/API mode

### Exploitation Toolkit
- Basic IDOR fuzzing
- Token replay and login bypass attempts
- Placeholder for expanded modules (JWT tampering, broken auth logic, etc.)

### Emulator Automation (NEW)
- Headless emulator provisioning via `--setup-emulator`
- Automatically creates and configures Android Virtual Device (AVD)
- Boots emulator with Frida preloaded
- Saves snapshot (`frida_ready`) for instant reuse in future runs

---

## Project Structure

```plaintext
MobileMorph/
├── main.py                            # Entry point CLI orchestrator
├── .gitignore
├── .github/workflows
│   ├── ci.yml
├── static/
│   ├── apk_static_analysis.py
│   ├── ipa_static_analysis.py
│   └── secrets_scanner.py
├── dynamic/
│   ├── dynamic_runner.py
│   ├── hook_loader.py                  # Loads Frida hook profiles
│   ├── traffic_analyzer.py
│   ├── traffic_interceptor.py
│   ├── traffic_interceptor_ios.py
│   ├── frida_hooks/
│   │   ├── auth_bypass.js
│   │   ├── bypass_ssl.js
│   │   ├── hook_crypto.js
│   │   ├── network_logger.js
│   │   ├── proxy_force.js
│   │   └── root_bypass.js
│   ├── mitm/
│   │   ├── modify_requests.py
│   ├── modules/
│   │   ├── logcat_monitor.py
│   │   └── storage_monitor.py
├── exploits/
│   └── exploit_runner.py
├── report/
│   └── report_generator.py
├── reports/                           # Generated output reports
├── tools/
│   └── frida-server
├── utils/
│   ├── burp_api_helper.py            
│   ├── emulator_manager.py            # Automates rooted emulator setup + snapshots
│   ├── file_utils.py
│   ├── frida_helpers.py
│   ├── logger.py
│   └── paths.py
├── README.md
└── requirements.txt
```

## Usage
### Run All Analyses
```bash
python3 main.py --apk path/to/app.apk --static --dynamic --exploit
```
### Static Analysis Only
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
### Emulator Setup with Snapshot (Frida-Ready)
```bash
python3 main.py --setup-emulator
```

## Attack Surface Coverage
- Insecure data storage (SharedPreferences, SQLite, local files)
- Insecure communication (HTTP, broken SSL pinning)
- Authentication bypass (login force, session tampering)
- Authorization flaws (IDOR replay, role tampering)
- Debug info leaks (via Logcat and traffic)
- Root detection bypass (hooked via Frida)
- Secrets in memory and local storage
- Active Burp Scanner tests against all runtime-discovered URLs

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
- iOS dynamic support (experimental)
- Expand Burp automation to support passive scanning and reporting import
- Integration with MobSF or Drozer-like module system
- Add signature bypass via runtime patching



👨‍💻 Author
Malik Smith
Built with ❤️ for advanced mobile app pentesting automation

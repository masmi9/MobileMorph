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

### Exploitation Toolkit
- Basic IDOR fuzzing
- Token replay and login bypass attempts
- Placeholder for expanded modules (JWT tampering, broken auth logic, etc.)

---

## Project Structure

```plaintext
MobileMorph/
├── main.py                            # Entry point CLI orchestrator
├── static/
│   ├── apk_static_analysis.py
│   ├── ipa_static_analysis.py
│   └── secrets_scanner.py
├── dynamic/
│   ├── dynamic_runner.py
│   ├── traffic_analyzer.py
│   ├── traffic_interceptor.py
│   ├── traffic_interceptor_ios.py
│   ├── frida_hooks/
│   │   ├── bypass_ssl.js
│   │   ├── hook_crypto.js
│   │   ├── network_logger.js
│   │   ├── auth_bypass.js
│   │   └── root_bypass.js
│   ├── modules/
│   │   ├── logcat_monitor.py
│   │   └── storage_monitor.py
├── exploits/
│   └── exploit_runner.py
├── report/
│   └── report_generator.py
├── reports/                           # Generated output reports
├── utils/
│   ├── logger.py
│   ├── frida_helpers.py
│   ├── file_utils.py
│   └── paths.py
└── requirements.txt

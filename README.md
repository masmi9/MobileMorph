# MobileMorph

**MobileMorph** is an automated mobile application penetration testing framework for APK and IPA files, designed for static and dynamic analysis. Built as a preparation and companion tool for professional mobile application security assessments.

---

## Features

- Static analysis of APK and IPA files  
- Hardcoded secrets discovery  
- SSL pinning bypass via Frida  
- API traffic interception with Burp or mitmproxy  
- Dynamic runtime hook scripts  
- Automated report generation (JSON/Markdown)

---

## Installation

```bash
git clone https://github.com/yourname/MobileMorph.git
cd MobileMorph
pip install -r requirements.txt
```

---

## Usage

**Static Analysis**
```bash
python main.py --static --apk /path/to/app.apk
python main.py --static --ipa /path/to/app.ipa
```

**Dynamic Analysis**
```bash
python main.py --dynamic --apk /path/to/app.apk
python main.py --dynamic --ipa /path/to/app.ipa
```

**Generate Report**
```bash
python main.py --report
```

---

## Workflow
```
         +---------------------------+
         | Decompile APK/IPA          |
         +---------------------------+
                     |
            (Static Analysis)
                     ↓
         +---------------------------+
         | Scan Manifest, Strings,    |
         | Extract Permissions, Detect|
         | Hardcoded Secrets          |
         +---------------------------+
                     |
          (Dynamic Analysis via Frida)
                     ↓
         +---------------------------+
         | Capture Network Traffic    |
         | Bypass SSL Pinning         |
         | Dump full HTTP traffic     |
         +---------------------------+
                     |
           (Exploit + Traffic Analysis)
                     ↓
         +---------------------------+
         | Analyze API tokens, secrets|
         | Find insecure WebView/API  |
         +---------------------------+
                     |
               (Report Phase)
                     ↓
         +---------------------------+
         | Professional Report Output |
         | Static + Dynamic + Exploit |
         +---------------------------+

User Command
 ├──> Static Analysis (--static) → Static Findings + Secrets
 ├──> Dynamic Analysis (--dynamic) → Frida + Traffic Capture
 ├──> Exploitation (--exploit) → APK/IPA Weaknesses
 ├──> Professional Report (--report) → HTML Report + Browser Launch

```
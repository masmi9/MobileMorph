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

**Static Analysis**
```bash
python main.py --dynamic --apk /path/to/app.apk
python main.py --dynamic --ipa /path/to/app.ipa
```

**Generate Report**
```bash
python main.py --report
```
#!/bin/bash

# === INPUT: APK file ===
APK_FILE="$1"
if [ -z "$APK_FILE" ]; then
    echo "Usage: $0 path/to/app.apk"
    exit 1
fi

if [ ! -f "$APK_FILE" ]; then
    echo "❌ APK file not found: $APK_FILE"
    exit 1
fi

# === PATH SETUP ===
APK_BASENAME=$(basename "$APK_FILE" .apk)
OUT_DIR="${APK_BASENAME}_output"
SMALI_DIR="${OUT_DIR}/smali"
DEX_FILE="${OUT_DIR}/classes.dex"
JAR_FILE="${OUT_DIR}/classes-dex2jar.jar"
JAVA_DIR="${OUT_DIR}/java"

# === TOOLS SETUP ===

# apktool check
if ! command -v apktool >/dev/null 2>&1; then
    echo "❌ apktool not installed. Install it and make sure it's in your PATH."
    exit 1
fi

# dex2jar
if command -v d2j-dex2jar.sh >/dev/null 2>&1; then
    DEX2JAR=$(command -v d2j-dex2jar.sh)
elif command -v d2j-dex2jar >/dev/null 2>&1; then
    DEX2JAR=$(command -v d2j-dex2jar)
elif [ -f "/usr/share/dex2jar/d2j-dex2jar.sh" ]; then
    DEX2JAR="/usr/share/dex2jar/d2j-dex2jar.sh"
elif [ -x "./dex-tools-2.1/d2j-dex2jar.sh" ]; then
    DEX2JAR="./dex-tools-2.1/d2j-dex2jar.sh"
else
    echo "❌ dex2jar not found. Try: sudo apt install dex2jar OR download it manually."
    exit 1
fi

# smali check
if command -v smali >/dev/null 2>&1; then
    SMALI_CMD="smali assemble"
elif [ -f "./smali.jar" ]; then
    SMALI_CMD="java -jar smali.jar assemble"
else
    echo "❌ smali not found. Install via pip or download from https://bitbucket.org/JesusFreke/smali/"
    exit 1
fi

# === CFR Decompiler Check ===
CFR_JAR="tools/cfr.jar"
if [ ! -f "$CFR_JAR" ]; then
    echo "❌ [ERROR] cfr.jar not found."
    echo "Download from: https://www.benf.org/other/cfr/"
    echo "Then place it in: $PWD as ./cfr.jar"
    exit 1
fi

# === START PROCESS ===

echo "🔧 Step 1: Decompiling APK with apktool..."
apktool d "$APK_FILE" -o "$OUT_DIR" -f || exit 1

echo "⚙️ Step 2: Reassembling smali to DEX..."
$SMALI_CMD -o "$DEX_FILE" "$SMALI_DIR" || exit 1

echo "📦 Step 3: Converting DEX to JAR with dex2jar..."
$DEX2JAR "$DEX_FILE" -o "$JAR_FILE" || exit 1

echo "🧠 Step 4: Decompiling JAR to Java with CFR..."
mkdir -p "$JAVA_DIR"
java -jar "$CFR_JAR" "$JAR_FILE" --outputdir "$JAVA_DIR" || exit 1

# === DONE ===
echo -e "\n✅ Success! Decompiled Java source saved to:"
echo "$JAVA_DIR"

#!/bin/bash

AVD_NAME="mobilemorph_emulator"
SYSTEM_IMAGE="system-images;android-30;google_apis;x86"
SNAPSHOT_NAME="frida_ready"
FRIDA_VERSION="16.1.6"
ARCH="x86"    # For emulator; change to arm64 for physical device

TOOLS_DIR="tools"
FRIDA_BINARY="$TOOLS_DIR/frida-server"

mkdir -p "$TOOLS_DIR"

# Function to download frida-server if not present
download_frida_server() {
  echo "[*] frida-server not found, attempting to download version $FRIDA_VERSION..."

  if [[ "$ARCH" == "x86" ]]; then
    PLATFORM="android-x86"
  elif [[ "$ARCH" == "arm64" ]]; then
    PLATFORM="android-arm64"
  else
    echo "[!] Unsupported architecture: $ARCH"
    exit 1
  fi

  FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-${PLATFORM}.xz"

  echo "[*] Downloading from $FRIDA_URL..."
  curl -L "$FRIDA_URL" -o "$FRIDA_BINARY.xz" || { echo "[!] Download failed."; exit 1; }

  echo "[*] Extracting frida-server..."
  xz -d "$FRIDA_BINARY.xz" || { echo "[!] Failed to extract."; exit 1; }
  chmod +x "$FRIDA_BINARY"
  echo "[+] frida-server ready: $FRIDA_BINARY"
}

# 1. Install system image if not already installed
echo "[*] Installing system image..."
yes | sdkmanager --install "$SYSTEM_IMAGE"

# 2. Create AVD if it doesn't exist
if ! avdmanager list avd | grep -q "$AVD_NAME"; then
  echo "[*] Creating AVD named $AVD_NAME..."
  echo "no" | avdmanager create avd -n "$AVD_NAME" -k "$SYSTEM_IMAGE" --force
fi

# 3. Start emulator with writable system
echo "[*] Starting emulator..."
$ANDROID_HOME/emulator/emulator -avd "$AVD_NAME" -no-window -no-audio -writable-system -selinux permissive &

# 4. Wait for emulator to boot
echo "[*] Waiting for device to boot..."
adb wait-for-device
BOOT_COMPLETED=""
until [[ "$BOOT_COMPLETED" == "1" ]]; do
  BOOT_COMPLETED=$(adb shell getprop sys.boot_completed | tr -d '\r')
  sleep 2
done
echo "[+] Emulator booted."

# 5. Gain root access and remount system
echo "[*] Gaining root access..."
adb root
sleep 2
echo "[*] Remounting /system as read-write..."
adb remount

# 6. Download frida-server if needed
if [[ ! -f "$FRIDA_BINARY" ]]; then
  download_frida_server
else
  echo "[✓] frida-server already exists at $FRIDA_BINARY"
fi

# 7. Push frida-server
echo "[*] Pushing frida-server..."
adb push tools/frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# 8. Save snapshot for quick boot
echo "[*] Saving emulator snapshot..."
adb emu avd snapshot save "$SNAPSHOT_NAME"

echo "[✓] Emulator setup complete with snapshot: $SNAPSHOT_NAME"



# Launch Emulator from Snapshot Later #
# emulator -avd mobilemorph_emulator -no-window -no-audio -snapshot frida_ready#
from  utils import frida_helpers

print('[INFO] Checking Frida version compatibility...')
if not frida_helpers.check_frida_version_match():
    raise SystemExit('[ERROR] Frida version do not match! Aborting workflow.')
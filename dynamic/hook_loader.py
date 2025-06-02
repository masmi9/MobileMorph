import os

# Map hook identifiers to script file paths (relative to project root)
HOOKS = {
    "bypass_jailbreak": "dynamic/frida_hooks/bypass_jailbreak.js",
    "hook_allmethods": "dynamic/frida_hooks/hook-allmethods.js",
    "hook_keychain": "dynamic/frida_hooks/hook_keychain.js",
    "hook_targetmethods": "dynamic/frida_hooks/hook-targetmethods.js",
    "intent_hook": "dynamic/frida_hooks/intent_hook.js",
    "network_logger": "dynamic/frida_hooks/network_logger.js",
    "proxy": "dynamic/frida_hooks/proxy_force.js",
    "security_providers": "dynamic/frida_hooks/get-security-providers.js",
    "webview_all": "dynamic/frida_hooks/webview-allmethods.js",
    "webview_target": "dynamic/frida_hooks/webview-targetmethods.js"
}

# Define reusable hook profiles
PROFILES = {
    "full": ["proxy", "network_logger", "hook_allmethods", "webview_all"],
    "minimal": ["network_logger"],
    "intent_monitor": ["intent_hook"],
    "ios_full": ["network_logger", "bypass_jailbreak", "hook_keychain"],
    "ios_minimal": ["bypass_jailbreak"],
    "method_hooking": ["hook_allmethods", "hook_targetmethods"],
    "security_check": ["security_providers", "root_bypass"],
    "webview_expanded": ["webview_all", "webview_target"]    
}

def load_hooks(profile_name):
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    selected_hooks = PROFILES.get(profile_name.lower())
    if not selected_hooks:
        raise ValueError(f"Profile '{profile_name}' not found. Available: {', '.join(PROFILES)}")

    loaded = []
    for name in selected_hooks:
        path = os.path.join(project_root, HOOKS[name])
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Hook file '{path}' does not exist")
        with open(path, 'r') as f:
            loaded.append((name, f.read()))
    return loaded

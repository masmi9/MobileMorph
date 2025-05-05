import os

# Map hook identifiers to script file paths (relative to project root)
HOOKS = {
    "network_logger": "dynamic/frida_hooks/network_logger.js",
    "hook_crypto": "dynamic/frida_hooks/hook_crypto.js",
    "bypass_ssl": "dynamic/frida_hooks/bypass_ssl.js",
    "auth_bypass": "dynamic/frida_hooks/auth_bypass.js",
    "root_bypass": "dynamic/frida_hooks/root_bypass.js",
    "proxy": "dynamic/frida_hooks/proxy_force.js",
}

# Define reusable hook profiles
PROFILES = {
    "full": ["proxy", "network_logger", "hook_crypto", "bypass_ssl", "auth_bypass", "root_bypass"],
    "minimal": ["network_logger"],
    "ssl_only": ["bypass_ssl"],
    "crypto_focus": ["hook_crypto"],
    "stealth": ["root_bypass", "bypass_ssl"],
    "proxy": ["proxy", "network_logger"]
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

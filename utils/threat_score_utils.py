def calculate_risk_score(results):
    risk_score = 0

    # Static findings (code-based detections)
    for finding in results.get("static_findings", []):
        if finding["type"] == "embedded_ssh_key":
            risk_score += 5
        elif finding["type"] == "ssh_command_exec":
            risk_score += 3
        elif finding["type"] == "ssh_config":
            risk_score += 2
        elif finding["type"] == "command_execution":
            risk_score += 3
        elif finding["type"] == "tainted_data_usage":
            risk_score += 3
        elif finding["type"] == "webview_usage":
            risk_score += 2
        elif finding["type"] == "reflection_usage":
            risk_score += 1
        elif finding["type"] == "base64_decode":
            risk_score += 1
        elif finding["type"] == "suspicious_url":
            risk_score += 2
        elif finding["type"] == "ssrf_potential":
            risk_score += 3

    # Exported components (unprotected Android components)
    exported = results.get("exported_components", [])
    risk_score += len(exported) * 1

    # Reflection usage
    reflection = results.get("reflection_usage", [])
    risk_score += len(reflection) * 1

    # Root detection logic (anti-analysis techniques)
    root = results.get("root_detection", [])
    risk_score += len(root) * 1

    # Secrets and hardcoded keys
    secrets = results.get("secrets", [])
    risk_score += len(secrets) * 2

    keys = results.get("hardcoded_keys", [])
    risk_score += len(keys) * 2

    # WebView configuration issues
    webview = results.get("webview_config", [])
    risk_score += len(webview) * 2

    # IOCs from strings and code
    iocs = results.get("ioc_candidates", [])
    risk_score += len(iocs) * 1

    # Dangerous Android permissions
    dangerous_perms = {
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.AUTHENTICATE_ACCOUNTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.CAMERA"
    }
    permissions = results.get("permissions", [])
    risk_score += sum(1 for p in permissions if p in dangerous_perms)

    # Finalize score and level
    results["risk_score"] = risk_score
    results["risk_level"] = classify_risk_level(risk_score)
    return results


def classify_risk_level(score):
    if score >= 30:
        return "High"
    elif score >= 15:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return "None"

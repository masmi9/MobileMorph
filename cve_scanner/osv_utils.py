import requests
import json

OSV_API = "https://api.osv.dev/v1/query"

def query_osv_for_package(name, version, ecosystem):
    payload = {
        "version": version,
        "package": {
            "name": name,
            "ecosystem": ecosystem  # e.g., "Maven", "npm", "PyPI"
        }
    }

    try:
        resp = requests.post(OSV_API, json=payload)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": f"OSV API error: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

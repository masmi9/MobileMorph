from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    if "api_key" in flow.request.pretty_url:
        flow.request.query["api_key"] = "fuzzed_value"
    if "Authorization" in flow.request.headers:
        flow.request.headers["Authorization"] = "Bearer FUZZEDTOKEN"

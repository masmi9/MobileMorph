import mitmproxy
from mitmproxy import http
import logging
from utils import logger

class TrafficInterceptor:
    def __init__(self):
        self.logger = logger
    
    # Intercepts HTTP requests and logs the URL and HTTP method.
    def request(self, flow: http.HTTPFlow) -> None:
        """Intercepts incoming HTTP requests."""
        self.logger.info(f"Intercepting request: {flow.request.method} {flow.request.url}")
        # You can add more logic here (e.g., modify requests or log headers, bodies, etc.)

    # Intercepts HTTP responses and logs the status code and URL.
    def response(self, flow: http.HTTPFlow) -> None:
        """Intercepts HTTP responses."""
        self.logger.info(f"Intercepting repsonse: {flow.request.method} {flow.request.url} - Status: {flow.response.status_code}")
        # Add more logic to handle responses (e.g., logging response body status code, etc.)

    # Starts the proxy server using mitmproxy, listening on port 8080 by default. You can change this port based on your testing requirements.
    def start_proxy(sefl, port=8080):
        """Starts the proxy server."""
        self.logger.info(f"Starting proxy server on port {port}...")
        from mitmproxy import proxy, options
        opts = options.Options(listen_host='0.0.0.0', listen_port=port)
        mproxy = proxy.ProxyServer(opts)
        mcontroller = mitmproxy.controller.DummyController()
        mcontroller.addons.add(self)
        mproxy.start()
// A simple Frida hook that intercepts HttpURLConnection requests

Java.perform(function () {
    var URL = Java.use('java.net.URL');
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');

    URL.openConnection.overload().implementation = function () {
        var urlStr = this.toString();
        send("[Network] URL opened: " + urlStr);
        var conn = this.openConnection();
        if (Java.cast(conn, HttpURLConnection)) {
            var httpConn = Java.cast(conn, HttpURLConnection);
            send("[Network] Method: " + httpConn.getRequestMethod());
            httpConn.connect.implementation = function () {
                send("[Network] Connecting to: " + urlStr);
                this.connect();
                send("[Network] Connected.");
            };
            // Optional: Log request headers
            httpConn.getRequestProperties.implementation = function () {
                var props = this.getRequestProperties();
                send("[Network] Headers: " + props.toString());
                return props;
            };
        }
        return conn;
    };
});


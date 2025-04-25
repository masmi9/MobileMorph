// A simple Frida hook that intercepts HttpURLConnection requests

Java.perform(function () {
    var URL = Java.use('java.net.URL');
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');

    URL.openConnection.overload().implementation = function () {
        var urlStr = this.toString();
        send("URL opened: " + urlStr);

        var conn = this.openConnection();

        // If it's an HTTP connection, log the request method too
        if (Java.cast(conn, HttpURLConnection)) {
            var httpConn = Java.cast(conn, HttpURLConnection);
            send("HTTP Method: " + httpConn.getRequestMethod());
        }

        return conn;
    };
});

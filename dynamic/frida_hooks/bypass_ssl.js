/* Purpose: This Frida script hooks into the SSL/TLS verification functions to bypass SSL pinning mechanisms used by many mobile apps. 
SSL pinning is used to prevent the app from accepting a fake certificate, thus protecting against man-in-the-middle attacks. */


// This script will bypass SSL Pinning by disabling SSL certificate validation
Java.perform(function () {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function (km, tm, sr) {
        var now = new Date();
        console.log("[SSL Bypass] Hook triggered at: " + now.toISOString());
        try {
            var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var MyTrustManager = Java.registerClass({
                name: "com.morph.MyTrustManager",
                implements: [TrustManager],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            console.log("[SSL Bypass] Custom TrustManager injected.");
            var trustManagers = [MyTrustManager.$new()];
            this.init(km, trustManagers, sr);
        } catch (e) {
            console.log("[SSL Bypass] Error during injection: " + e);
        }
    };
});

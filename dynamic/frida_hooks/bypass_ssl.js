/* Purpose: This Frida script hooks into the SSL/TLS verification functions to bypass SSL pinning mechanisms used by many mobile apps. 
SSL pinning is used to prevent the app from accepting a fake certificate, thus protecting against man-in-the-middle attacks. */


// This script will bypass SSL Pinning by disabling SSL certificate validation
Java.perform(function () {
    // Hooking into the SSLContext class
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    // Overriding the init method to bypass SSL validation
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "{Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function (km, tm, sr) {
        console.log("Bypassing SSL Pinning...");
        // Use a TrustManager that accepts all certificates
        var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var allTrustManager = Java.registerClass({
            name: "com.morph.MyTrustManager",
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var allTrustManagers = [allTrustManager.$new()];
        // Call the original SSLContext.init method with our TrustManager
        this.init(km, allTrustManagers, sr);
    };
});

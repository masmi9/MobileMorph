/* Purpose: This script is used to hook into cryptographic functions (like AES, RSA, etc.) to observe or modify data passed to these 
functions. This is useful when analyzing how sensitive data is encrypted or decrypted in the application.*/


// This script will hook into various cryptographic methods like AES and RSA
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
        var now = new Date();
        console.log("[Crypto] Cipher.doFinal() called at: " + now.toISOString());
        function toHex(array) {
            return Array.prototype.map.call(array, function (byte) {
                return ('0' + (byte & 0xFF).toString(16)).slice(-2);
            }).join('');
        }
        console.log("[Crypto] Input (hex): " + toHex(input));
        var result = this.doFinal(input);
        console.log("[Crypto] Result (hex): " + toHex(result));
        return result;
    };
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload("java.lang.String").implementation = function (algorithm) {
        console.log("[Crypto] Hash algorithm used: " + algorithm);
        return this.getInstance(algorithm);
    };
});

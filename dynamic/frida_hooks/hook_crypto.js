/* Purpose: This script is used to hook into cryptographic functions (like AES, RSA, etc.) to observe or modify data passed to these 
functions. This is useful when analyzing how sensitive data is encrypted or decrypted in the application.*/


// This script will hook into various cryptographic methods like AES and RSA
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");

    // Hooking the Cipher class' doFinal method
    Cipher.doFinal.overload("[B").implementation = function (input) {
        console.log("Cipher.doFinal() called");
        console.log("Input: " + input.toString());

        // Call the original method to continue execution
        var result = this.doFinal(input);

        console.log("Result: " + result.toString());
        return result;
    };

    // Hooking the MessageDigest class for hashing
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload("java.lang.String").implementation = function (algorithm) {
        console.log("MessageDigest.getInstance() called with algorithm: " + algorithm);
        return this.getInstance(algorithm); // Return the original instance
    };
});

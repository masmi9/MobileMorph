Java.perform(function () {
    // SET TARGET CLASS TO HOOK METHODS FOR:
    // Example: set to "android.webkit.WebView" to hook all methods of the WebView class
    var targetClassStr = "PACKAGE_NAME.CLASS_NAME";
    var targetClass = Java.use(targetClassStr);

    // SET TARGET METHODS TO HOOK:
    // Example: set to ["getUrl", "loadUrl", "loadData", "postUrl", "addJavascriptInterface", "evaluateJavascript", "setWebContentsDebuggingEnabled"] to hook specific WebView methods
    var targetMethods = ["METHOD1", "METHOD2", "METHOD3"];

    console.log("\n[*] Hook target methods of " + targetClassStr);
    console.log("[*] Excluding null and undefined arguments and return values");

    // Iterate over each method
    targetMethods.forEach(function (method) {
        //var methodName = method.getName();
        console.log("[+] Hooking " + targetClassStr + "." + method);
        var overloads = targetClass[method].overloads;

        // Hook each overload of the method
        overloads.forEach(function (overload) {
            overload.implementation = function () {
                // Build a string of argument values
                var argsString = "";
                for (var i = 0; i < arguments.length; i++) {
                    try {
                        // Handle null or primitive types
                        if (arguments[i] === null || arguments[i] === undefined) {
                            argsString += "arg" + i + ": null";
                        } else {
                            // Convert to string, safely handling objects
                            argsString += "arg" + i + ": " + arguments[i].toString();
                        }
                    } catch (e) {
                        argsString += "arg" + i + ": [unreadable]";
                    }
                    if (i < arguments.length - 1) argsString += ", ";
                }

                // Log method entry with arguments
                if (arguments.length > 0) console.log("[>] " + targetClassStr + "." + method + " called with: [" + argsString + "]");

                // Call the original method and capture the return value
                var returnValue = overload.apply(this, arguments);

                // Log method exit with return value
                try {
                    if (returnValue != null && returnValue != undefined) console.log("[<] " + targetClassStr + "." + method + " returned: " + returnValue.toString());
                } catch (e) {
                    console.log("[<] " + targetClassStr + "." + method + " returned: [unreadable]");
                }
                
                // Return the original result to the app
                return returnValue;
            };
        });
    });

});

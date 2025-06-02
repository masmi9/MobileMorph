Java.perform(function () {
    console.log("\n[*] Hook target methods of android.webkit.WebView");
    console.log("[*] Excluding null and undefined arguments and return values");
    console.log("[*] Saving output to /sdcard/webview_trace.log");

    // Save console output to a file on the Android device
    var outputFile = new File("/sdcard/webview_trace.log", "a");

    // Function to log to console and log file
    function logOutput(message) {
        console.log(message);
        outputFile.write(message + "\n");
    }

    // Hook the android.webkit.WebView class
    var WebView = Java.use("android.webkit.WebView");

    // Get all methods of the WebView class
    var methods = WebView.class.getDeclaredMethods();

    // Iterate over each method
    methods.forEach(function (method) {
        var methodName = method.getName();
        console.log("[+] Hooking WebView." + method);
        var overloads = WebView[methodName].overloads;

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
                if (arguments.length > 0) logOutput("[>] WebView." + methodName + " called with: [" + argsString + "]");

                // Call the original method and capture the return value
                var returnValue = overload.apply(this, arguments);

                // Log method exit with return value
                try {
                    if (returnValue != null && returnValue != undefined) logOutput("[<] WebView." + methodName + " returned: " + returnValue.toString());
                } catch (e) {
                    logOutput("[<] WebView." + methodName + " returned: [unreadable]");
                }

                // Return the original result to the app
                return returnValue;
            };
        });
    });

});

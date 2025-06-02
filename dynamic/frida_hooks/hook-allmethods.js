Java.perform(function () {
    // SET TARGET CLASS TO HOOK METHODS FOR:
    // Example: set to "android.webkit.WebView" to hook all methods of the WebView class
    var targetClassStr = "PACKAGE_NAME.CLASS_NAME"; 
    
    console.log("\n[*] Hook all methods of " + targetClassStr);
    console.log("[*] Excluding null and undefined arguments and return values");

    // Hook the java.io.targetClass class
    var targetClass = Java.use(targetClassStr);

    // Get all methods of the targetClass class
    var methods = targetClass.class.getDeclaredMethods();

    // Iterate over each method
    methods.forEach(function (method) {
        var methodName = method.getName();
        console.log("[+] Hooking " + targetClassStr + "." + method);
        var overloads = targetClass[methodName].overloads;

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
                if (arguments.length > 0) console.log("[>] " + targetClassStr + "." + methodName + " called with: [" + argsString + "]");

                // Call the original method and capture the return value
                var returnValue = overload.apply(this, arguments);

                // Log method exit with return value
                try {
                    if (returnValue != null && returnValue != undefined) console.log("[<] " + targetClassStr + "." + methodName + " returned: " + returnValue.toString());
                } catch (e) {
                    console.log("[<] " + targetClassStr + "." + methodName + " returned: [unreadable]");
                }

                // Return the original result to the app
                return returnValue;
            };
        });
    });

});

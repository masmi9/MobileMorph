// dynamic/frida_hooks/root_bypass.js

console.log("[*] Starting Root Detection Bypass Hook...");

Java.perform(function () {
    // 1. Bypass isRooted() or similar custom root checks
    var rootDetectionClasses = [
        "com.example.security.RootDetection",
        "com.example.util.DeviceUtils",
        "com.scottyab.rootbeer.RootBeer",
        "com.noshufou.android.su.SuChecker"
        // Add more as needed
    ];

    rootDetectionClasses.forEach(function(className) {
        try {
            var clazz = Java.use(className);

            if (clazz.isRooted) {
                clazz.isRooted.implementation = function () {
                    console.log("[+] isRooted() hooked: returning FALSE");
                    return false;
                };
            }

            if (clazz.detectRoot) {
                clazz.detectRoot.implementation = function () {
                    console.log("[+] detectRoot() hooked: returning FALSE");
                    return false;
                };
            }

            console.log("[*] Hooked root detection class:", className);
        } catch (err) {
            console.log("[-] Failed to hook class " + className + ": " + err);
        }
    });

    // 2. Override File.exists() for common root paths
    var File = Java.use("java.io.File");

    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.includes("su") || path.includes("busybox") || path.includes("magisk")) {
            console.log("[+] Fake exists() for path:", path, "-> FALSE");
            return false;
        }
        return this.exists();
    };

    // 3. Bypass Runtime.exec("su") or similar
    var Runtime = Java.use("java.lang.Runtime");

    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd.includes("su")) {
            console.log("[+] Blocked Runtime.exec command:", cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
        var cmd = cmdArray.join(" ");
        if (cmd.includes("su")) {
            console.log("[+] Blocked Runtime.exec array command:", cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmdArray);
    };

    // 4. Override Build.TAGS and ro.build properties
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";  // Avoid "test-keys" detection
    console.log("[*] Overriding Build.TAGS to 'release-keys'");

    // 5. System.getProperty to hide root flags
    var System = Java.use("java.lang.System");
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        if (key === "ro.build.tags") {
            console.log("[+] getProperty('ro.build.tags') -> release-keys");
            return "release-keys";
        }
        return this.getProperty(key);
    };
});

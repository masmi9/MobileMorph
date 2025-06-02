console.log("[*] Injected Keychain hook script");

const SecItemCopyMatching = Module.findExportByName(null, "SecItemCopyMatching");
const SecItemAdd = Module.findExportByName(null, "SecItemAdd");

function printNSDictionary(dictPtr) {
    const ObjC = global.ObjC;
    if (!ObjC.available) return "[!] ObjC not available";

    try {
        const dict = new ObjC.Object(dictPtr);
        return dict.toString();
    } catch (err) {
        return "[!] Failed to parse NSDictionary: " + err;
    }
}

Interceptor.attach(SecItemCopyMatching, {
    onEnter: function (args) {
        console.log("[Keychain] SecItemCopyMatching called");
        console.log("Query:", printNSDictionary(args[0]));
    },
    onLeave: function (retval) {
        console.log("[Keychain] SecItemCopyMatching result:", retval);
    }
});

Interceptor.attach(SecItemAdd, {
    onEnter: function (args) {
        console.log("[Keychain] SecItemAdd called");
        console.log("Data:", printNSDictionary(args[0]));
    },
    onLeave: function (retval) {
        console.log("[Keychain] SecItemAdd result:", retval);
    }
});

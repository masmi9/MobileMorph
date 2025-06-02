console.log("[*] Injected jailbreak bypass script");

function fake_stat(pathPtr) {
    var path = Memory.readUtf8String(pathPtr);
    if (path.indexOf("Cydia") !== -1 ||
        path.indexOf("MobileSubstrate") !== -1 ||
        path.indexOf("Applications") !== -1) {
        console.log("[!] Bypassing stat on suspicious path: " + path);
        return -1; // simulate file not found
    }
    return this.stat(pathPtr);
}

Interceptor.attach(Module.findExportByName(null, "stat"), {
    onEnter: function (args) {
        this.pathPtr = args[0];
    },
    onLeave: function (retval) {
        retval.replace(fake_stat.call(this, this.pathPtr));
    }
});

Interceptor.replace(Module.findExportByName(null, "fork"), new NativeCallback(function () {
    console.log("[!] fork() called – returning dummy pid");
    return 1234;
}, 'int', []));

Interceptor.replace(Module.findExportByName(null, "ptrace"), new NativeCallback(function (req, pid, addr, data) {
    console.log("[!] ptrace() bypassed – anti-debug neutralized");
    return 0;
}, 'int', ['int', 'int', 'pointer', 'int']));

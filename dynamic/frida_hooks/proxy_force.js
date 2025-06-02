Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.setProperty('http.proxyHost', '127.0.0.1');
    System.setProperty('http.proxyPort', '8080');
    console.log("Forced app to use proxy 127.0.0.1:8080");
});

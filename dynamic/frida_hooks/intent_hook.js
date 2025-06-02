Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
        console.log("[*] startActivity called with Intent: " + intent.toString());
        console.log("[*] Extras: " + intent.getExtras());
        return this.startActivity(intent);
    };

    var Context = Java.use("android.content.Context");
    Context.sendBroadcast.overload('android.content.Intent').implementation = function (intent) {
        console.log("[*] sendBroadcast called with Intent: " + intent.toString());
        return this.sendBroadcast(intent);
    };
});

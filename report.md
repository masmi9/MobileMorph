# OWASP Mobile Top 10 Security Report

This report contains the findings from the automated OWASP Mobile Top 10 security tests.

## M1: Improper Platform Usage
Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Package: com.bd.nproject
  Application Label: Lemon8
  Process Name: com.bd.nproject
  Version: 8.6.5
  Data Directory: /data/user/0/com.bd.nproject
  APK Path: /data/app/com.bd.nproject-CRUnYK1pzhyeEsg7bb-LDA==/base.apk
  UID: 10085
  GID: [3003]
  Shared Libraries: null
  Shared User ID: null
  Uses Permissions:
  - android.permission.VIBRATE
  - android.permission.GET_ACCOUNTS
  - android.permission.AUTHENTICATE_ACCOUNTS
  - android.permission.WRITE_SYNC_SETTINGS
  - android.permission.ACCESS_NETWORK_STATE
  - android.permission.INTERNET
  - android.permission.WAKE_LOCK
  - android.permission.WRITE_EXTERNAL_STORAGE
  - android.permission.READ_EXTERNAL_STORAGE
  - android.permission.READ_MEDIA_IMAGES
  - android.permission.READ_MEDIA_VIDEO
  - android.permission.POST_NOTIFICATIONS
  - com.google.android.gms.permission.AD_ID
  - android.permission.CHANGE_WIFI_STATE
  - android.permission.ACCESS_WIFI_STATE
  - android.permission.ACCESS_COARSE_LOCATION
  - android.permission.RECORD_AUDIO
  - android.permission.CAMERA
  - MediaStore.Images.Media.INTERNAL_CONTENT_URI
  - MediaStore.Images.Media.EXTERNAL_CONTENT_URI
  - com.android.launcher.permission.INSTALL_SHORTCUT
  - com.android.launcher.permission.UNINSTALL_SHORTCUT
  - com.google.android.c2dm.permission.RECEIVE
  - com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE
  - com.bd.nproject.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
  Defines Permissions:
  - com.bd.nproject.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION


Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Package: com.bd.nproject
  com.bytedance.nproject.app.MainActivity
    Permission: null
  com.bytedance.sdk.account.OneTapLoginActivity
    Permission: null
  com.bytedance.nproject.router.impl.ui.RouteActivity
    Permission: null
  com.bytedance.nproject.router.impl.ui.Lemon8AppLinkActivity
    Permission: null
  com.bytedance.nproject.router.impl.ui.Lemon8LongLinkAppLinkActivity
    Permission: null
  com.bytedance.nproject.router.impl.ui.BrowserRouteActivity
    Permission: null
  com.bytedance.nproject.share.impl.sharett.TTShareActivity
    Permission: null
  com.bytedance.nproject.push.impl.settings.PushSettingsActivity
    Permission: null
  com.bytedance.common.ttauth.activity.TiktokAuthActivity
    Permission: null
  com.facebook.CustomTabActivity
    Permission: null


Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Package: com.bd.nproject
  com.appsflyer.MultipleInstallBroadcastReceiver
    Permission: null
  com.google.firebase.iid.FirebaseInstanceIdReceiver
    Permission: com.google.android.c2dm.permission.SEND
  androidx.profileinstaller.ProfileInstallReceiver
    Permission: android.permission.DUMP


Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Package: com.bd.nproject
  Authority: com.facebook.app.FacebookContentProvider426786581540674
    Read Permission: null
    Write Permission: null
    Content Provider: com.facebook.FacebookContentProvider
    Multiprocess Allowed: False
    Grant Uri Permissions: False



## Attack Surface Analysis
Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Package: com.bd.nproject
  com.bytedance.nproject.app.MainActivity
    Permission: null
  com.bytedance.sdk.account.OneTapLoginActivity
    Permission: null
  com.bytedance.nproject.router.impl.ui.RouteActivity
    Permission: null
  com.bytedance.nproject.router.impl.ui.Lemon8AppLinkActivity
    Permission: null
  com.bytedance.nproject.router.impl.ui.Lemon8LongLinkAppLinkActivity
    Permission: null
  com.bytedance.nproject.router.impl.ui.BrowserRouteActivity
    Permission: null
  com.bytedance.nproject.share.impl.sharett.TTShareActivity
    Permission: null
  com.bytedance.nproject.push.impl.settings.PushSettingsActivity
    Permission: null
  com.bytedance.common.ttauth.activity.TiktokAuthActivity
    Permission: null
  com.facebook.CustomTabActivity
    Permission: null


Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Package: com.bd.nproject
  com.bytedance.nproject.account.impl.init.AccountAuthService
    Permission: null
  com.google.android.gms.auth.api.signin.RevocationBoundService
    Permission: com.google.android.gms.auth.api.signin.permission.REVOCATION_NOTIFICATION
  com.ss.android.message.NotifyService
    Permission: null


Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Package: com.bd.nproject
  com.appsflyer.MultipleInstallBroadcastReceiver
    Permission: null
  com.google.firebase.iid.FirebaseInstanceIdReceiver
    Permission: com.google.android.c2dm.permission.SEND
  androidx.profileinstaller.ProfileInstallReceiver
    Permission: android.permission.DUMP


Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Package: com.bd.nproject
  Authority: com.facebook.app.FacebookContentProvider426786581540674
    Read Permission: null
    Write Permission: null
    Content Provider: com.facebook.FacebookContentProvider
    Multiprocess Allowed: False
    Grant Uri Permissions: False


Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Attack Surface:
  10 activities exported
  3 broadcast receivers exported
  1 content providers exported
  3 services exported


## Insecure Data Storage
Exception occured: unrecognized arguments: -a
Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module


## Shared Preferences
[+] Shared Preferences found:
SP_EXPERIMENT_CACHE.xml
SP_EXPERIMENT_EXPOSURE_CACHE.xml
WebViewChromiumPrefs.xml
com.facebook.internal.preferences.APP_GATEKEEPERS.xml
com.facebook.internal.preferences.APP_SETTINGS.xml
com.facebook.sdk.DataProcessingOptions.xml
com.facebook.sdk.USER_SETTINGS.xml
com.facebook.sdk.appEventPreferences.xml
com.facebook.sdk.attributionTracking.xml
com.ss.android.deviceregister.utils.Cdid.xml
multi_process_config.xml
ss_app_config.xml
ttnet_tnc_config.xml

## Traversal Vulnerabilities
We lost your drozer session.

For some reason the mobile Agent has stopped responding. You will need to restart it, and try again.

Selecting 1ee79d7e179c1a49 (Corellium Corellium Generic 8.1.0)

Attempting to run shell module
Scanning com.bd.nproject...
TimeoutError
<class 'RuntimeError'>
yayerroryay you probably didn't specify a valid drozer server and that's why you're seeing this error message
TimeoutError
<class 'RuntimeError'>
yayerroryay you probably didn't specify a valid drozer server and that's why you're seeing this error message


## Injection Vulnerabilities
[!] Command 'run scanner.provider.injection -a com.bd.nproject' failed: 'ConnectionError' object has no attribute 'message'

<class 'RuntimeError'>
yayerroryay you probably didn't specify a valid drozer server and that's why you're seeing this error message

## Additional Information (Deep Links, URLs, IPs)
[+] Deep Links Found:
fbconnect://cct.com.bd.nproject

[+] URLs Found:
http://ns.adobe.com/xap/1.0/\u0000
https://i.isnssdk.com/monitor/collect/c/logcollect
https://lemon8-sg.tiktok-row.net\
https://%sapp.%s
https://%sstats.%s/stats
https://%s/%s
http://schemas.android.com/tools
https://%sviap.%s/api/v1/android/validate_purchase?app_id=
https://%smonitorsdk.%s/remote-debug?app_id=
https://%sgcdsdk.%s/install_data/v4.0/
https://%sdlsdk.%s/v1.0/android/
https://mon.isnssdk.com/monitor/collect/
https://play.google.com/store/apps/details?id=
https://play.google.com/store
http://schemas.android.com/aapt
https://lemon8-va.tiktok-row.net\
https://cdn-testsettings.%s/android/v1/%s/settings
http://schemas.android.com/apk/res/android
https://%svalidate.%s/api/v
https://%sattr.%s/api/v
https://%simpression.%s
https://www.lemon8-app.com\
https://%sonelink.%s/shortlink-sdk/v2
https://cdn-settings.%s/android/v1/%s/settings
https://%sconversions.%s/api/v
https://%sinapps.%s/api/v
http://schemas.android.com/apk/res-auto
https://%sadrevenue.%s/api/v2/generic/v6.9.1/android?app_id=
https://www.lemon8-app.com/poi/
https://%sregister.%s/api/v
https://lf-main-gecko-source.tiktokcdn.com/obj/tiktok-teko-source-sg/
https://%sars.%s/api/v2/android/validate_subscription?app_id=
https://nproject-2657.firebaseio.com
https://%slaunches.%s/api/v
https://issuetracker.google.com/issues/116541301
https://%ssdk-services.%s/validate-android-signature
https://mon.isnssdk.com/monitor/appmonitor/v2/settings
https://developer.android.com/studio/build/shrink-code.html#keep-resources
https://lemon8-app.com

[+] IP Addresses Found:
4.2.137.118
2.1.25.0
5.0.21.12
1.7.0.4

## Insufficient Cryptography (M5)
[!] Potential plaintext keys or secrets found:
/data/data/com.bd.nproject/shared_prefs/com.facebook.internal.preferences.APP_GATEKEEPERS.xml:    <string name="com.facebook.internal.APP_GATEKEEPERS.426786581540674">{&quot;data&quot;:[{&quot;gatekeepers&quot;:[{&quot;key&quot;:&quot;FBSDKFeatureInstrument&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureCrashReport&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureAnrReport&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureRestrictiveDataFiltering&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureCodelessEvents&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureErrorReport&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureAAMR1&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureAAMR2&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureAAM&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureSuggestedEvents&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureCrashShield&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureThreadCheck&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeaturePrivacyProtection&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeaturePIIFiltering&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureAddressDetectionSample&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureMTML&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureModelRequest&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureEventDeactivation&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureChromeCustomTabsUpdate&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureChromeCustomTabsPrefetching&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureIntelligentIntegrity&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureIntegritySample&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureMonitoring&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureATELogging&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureOnDeviceEventProcessing&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureOnDevicePostInstallEventProcessing&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureSKAdNetwork&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureSKAdNetworkConversionValue&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureSKAdNetworkV4&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureIAPLogging&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureIAPLoggingLib2&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureIAPLoggingLib5To7&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureAndroidManualImplicitPurchaseDedupe&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureAndroidIAPSubscriptionAutoLogging&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureAndroidManualImplicitSubsDedupe&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureUshbaLogin&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureBypassAppSwitch&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureWebViewSchemeFiltering&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureAEM&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureAppEventsCloudbridge&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureServiceUpdateCompliance&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureAEMConversionFiltering&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureAEMCatalogMatching&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureAEMAdvertiserRuleMatchInServer&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureMegatron&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureElora&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureAppAemAutoSetUp&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureProtectedMode&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureAppAemAutoSetUpProxy&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureMACARuleMatching&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureBlocklistEvents&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureFilterRedactedEvents&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureFilterSensitiveParams&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureStdParamEnforcement&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureIAPLoggingSK2&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureIOSManualImplicitPurchaseDedupe&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureBannedParamFiltering&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;FBSDKFeatureGPSARATriggers&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureGPSPACAProcessing&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;FBSDKFeatureGPSTopicsObservation&quot;,&quot;value&quot;:false},{&quot;key&quot;:&quot;app_events_if_auto_log_subs&quot;,&quot;value&quot;:true},{&quot;key&quot;:&quot;app_events_killswitch&quot;,&quot;value&quot;:false}]}]}</string>


## Debuggable and Logging Checks
[+] App is not debuggable.


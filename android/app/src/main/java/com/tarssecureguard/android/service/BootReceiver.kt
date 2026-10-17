package com.tarssecureguard.android.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.preference.PreferenceManager

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            val prefs = PreferenceManager.getDefaultSharedPreferences(context)
            val autoStart = prefs.getBoolean("boot_autostart", false)
            if (autoStart) {
                Log.i("TSGBoot", "Boot completed, auto-starting TSG service")
                val mgr = ServiceManager(context)
                mgr.startService()
            }
        }
    }
}

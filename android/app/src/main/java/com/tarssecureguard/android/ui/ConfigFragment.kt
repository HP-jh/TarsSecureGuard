package com.tarssecureguard.android.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.preference.PreferenceManager
import com.tarssecureguard.android.R
import com.tarssecureguard.android.service.ServiceManager
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class ConfigFragment : Fragment() {

    private lateinit var addrInput: EditText
    private lateinit var autoStartSwitch: Switch
    private lateinit var gatewaySwitch: Switch
    private lateinit var maxLogInput: EditText
    private lateinit var saveBtn: Button
    private lateinit var statusText: TextView

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_config, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        addrInput = view.findViewById(R.id.config_addr)
        autoStartSwitch = view.findViewById(R.id.config_autostart)
        gatewaySwitch = view.findViewById(R.id.config_gateway)
        maxLogInput = view.findViewById(R.id.config_maxlog)
        saveBtn = view.findViewById(R.id.btn_save_config)
        statusText = view.findViewById(R.id.config_status)

        val prefs = PreferenceManager.getDefaultSharedPreferences(requireContext())
        addrInput.setText(prefs.getString("listen_addr", "127.0.0.1:18080"))
        autoStartSwitch.isChecked = prefs.getBoolean("boot_autostart", false)
        gatewaySwitch.isChecked = prefs.getBoolean("gateway_enabled", true)
        maxLogInput.setText(prefs.getInt("max_log_size_mb", 10).toString())

        saveBtn.setOnClickListener { saveConfig() }
        loadFromService()
    }

    private fun saveConfig() {
        val prefs = PreferenceManager.getDefaultSharedPreferences(requireContext())
        prefs.edit()
            .putString("listen_addr", addrInput.text.toString())
            .putBoolean("boot_autostart", autoStartSwitch.isChecked)
            .putBoolean("gateway_enabled", gatewaySwitch.isChecked)
            .putInt("max_log_size_mb", maxLogInput.text.toString().toIntOrNull() ?: 10)
            .apply()
        statusText.text = "已保存到本地"
        Toast.makeText(requireContext(), "配置已保存", Toast.LENGTH_SHORT).show()
    }

    private fun loadFromService() {
        val mgr = ServiceManager(requireContext())
        if (!mgr.isRunning()) return
        thread {
            try {
                val conn = URL("http://127.0.0.1:18080/api/config").openConnection() as HttpURLConnection
                conn.connectTimeout = 2000
                conn.readTimeout = 2000
                val body = conn.inputStream.bufferedReader().readText()
                val json = JSONObject(body)
                requireActivity().runOnUiThread {
                    addrInput.setText(json.optString("listen_addr", "127.0.0.1:18080"))
                    autoStartSwitch.isChecked = json.optBoolean("boot_auto_start", false)
                    gatewaySwitch.isChecked = json.optBoolean("gateway_enabled", true)
                    statusText.text = "已从服务同步"
                }
            } catch (_: Exception) { }
        }
    }
}

package com.tarssecureguard.android.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.tarssecureguard.android.R
import com.tarssecureguard.android.service.ServiceManager
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class StatusFragment : Fragment() {

    private lateinit var runningText: TextView
    private lateinit var uptimeText: TextView
    private lateinit var agentsText: TextView
    private lateinit var devicesText: TextView
    private lateinit var quarantinedText: TextView

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_status, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        runningText = view.findViewById(R.id.status_running)
        uptimeText = view.findViewById(R.id.status_uptime)
        agentsText = view.findViewById(R.id.status_agents)
        devicesText = view.findViewById(R.id.status_devices)
        quarantinedText = view.findViewById(R.id.status_quarantined)

        view.findViewById<View>(R.id.btn_refresh).setOnClickListener { refresh() }
        refresh()
    }

    private fun refresh() {
        val mgr = ServiceManager(requireContext())
        if (!mgr.isRunning()) {
            runningText.text = "服务未运行"
            uptimeText.text = "—"
            agentsText.text = "—"
            devicesText.text = "—"
            quarantinedText.text = "—"
            return
        }
        thread {
            try {
                val conn = URL("http://127.0.0.1:18080/api/status").openConnection() as HttpURLConnection
                conn.connectTimeout = 2000
                conn.readTimeout = 2000
                val body = conn.inputStream.bufferedReader().readText()
                val json = JSONObject(body)
                requireActivity().runOnUiThread {
                    runningText.text = "运行中"
                    uptimeText.text = "%.1f 秒".format(json.optDouble("uptime", 0.0))
                    val gw = json.optJSONObject("gateway") ?: JSONObject()
                    agentsText.text = gw.optInt("agents", 0).toString()
                    devicesText.text = "${gw.optInt("devices", 0)} (可信: ${gw.optInt("trustedDevices", 0)})"
                    quarantinedText.text = gw.optInt("quarantined", 0).toString()
                }
            } catch (e: Exception) {
                requireActivity().runOnUiThread {
                    runningText.text = "无法连接: ${e.message}"
                }
            }
        }
    }
}

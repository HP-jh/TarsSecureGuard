package com.tarssecureguard.android.ui

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.FileProvider
import androidx.fragment.app.Fragment
import com.tarssecureguard.android.R
import com.tarssecureguard.android.service.ServiceManager
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class LogsFragment : Fragment() {

    private lateinit var listView: ListView
    private lateinit var statusText: TextView
    private lateinit var refreshBtn: Button
    private lateinit var shareBtn: Button
    private var selectedFile: String? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_logs, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        listView = view.findViewById(R.id.logs_list)
        statusText = view.findViewById(R.id.logs_status)
        refreshBtn = view.findViewById(R.id.btn_refresh_logs)
        shareBtn = view.findViewById(R.id.btn_share_log)

        listView.setOnItemClickListener { _, _, position, _ ->
            (listView.adapter.getItem(position) as? String)?.let {
                selectedFile = it
                statusText.text = "选中: $it"
            }
        }

        refreshBtn.setOnClickListener { loadLogs() }
        shareBtn.setOnClickListener { shareSelected() }
        loadLogs()
    }

    private fun loadLogs() {
        val mgr = ServiceManager(requireContext())
        if (!mgr.isRunning()) {
            statusText.text = "服务未运行"
            listView.adapter = null
            return
        }
        thread {
            try {
                val conn = URL("http://127.0.0.1:18080/api/logs").openConnection() as HttpURLConnection
                conn.connectTimeout = 2000
                conn.readTimeout = 2000
                val body = conn.inputStream.bufferedReader().readText()
                val arr = JSONObject("{\"items\":$body}").getJSONArray("items")
                val names = mutableListOf<String>()
                for (i in 0 until arr.length()) {
                    val item = arr.getJSONObject(i)
                    names.add("${item.optString("name")} (${item.optInt("size")} bytes)")
                }
                requireActivity().runOnUiThread {
                    listView.adapter = ArrayAdapter(
                        requireContext(),
                        android.R.layout.simple_list_item_1,
                        names
                    )
                    statusText.text = "共 ${names.size} 个日志文件"
                }
            } catch (e: Exception) {
                requireActivity().runOnUiThread {
                    statusText.text = "获取失败: ${e.message}"
                }
            }
        }
    }

    private fun shareSelected() {
        val name = selectedFile
        if (name == null) {
            Toast.makeText(requireContext(), "请先选中一个日志文件", Toast.LENGTH_SHORT).show()
            return
        }
        // Download log via service to app cache
        val mgr = ServiceManager(requireContext())
        if (!mgr.isRunning()) {
            Toast.makeText(requireContext(), "服务未运行", Toast.LENGTH_SHORT).show()
            return
        }
        thread {
            try {
                val cleanName = name.substringBefore(' ')
                val conn = URL("http://127.0.0.1:18080/api/logs/download?name=$cleanName").openConnection() as HttpURLConnection
                conn.connectTimeout = 2000
                conn.readTimeout = 5000
                val data = conn.inputStream.readBytes()
                val cacheFile = File(requireContext().cacheDir, cleanName)
                cacheFile.writeBytes(data)
                val uri = FileProvider.getUriForFile(
                    requireContext(),
                    "com.tarssecureguard.android.fileprovider",
                    cacheFile
                )
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                startActivity(Intent.createChooser(intent, "分享日志"))
            } catch (e: Exception) {
                requireActivity().runOnUiThread {
                    Toast.makeText(requireContext(), "分享失败: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}

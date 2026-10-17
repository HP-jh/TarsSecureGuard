package com.tarssecureguard.android.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.tarssecureguard.android.R
import com.tarssecureguard.android.service.ServiceManager

class ControlFragment : Fragment() {

    private lateinit var statusText: TextView
    private lateinit var startBtn: Button
    private lateinit var stopBtn: Button

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_control, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        statusText = view.findViewById(R.id.control_status)
        startBtn = view.findViewById(R.id.btn_start)
        stopBtn = view.findViewById(R.id.btn_stop)

        val mgr = ServiceManager(requireContext())
        statusText.text = if (mgr.isRunning()) "服务运行中" else "服务未启动"
        startBtn.isEnabled = !mgr.isRunning()
        stopBtn.isEnabled = mgr.isRunning()

        startBtn.setOnClickListener {
            mgr.startService()
            statusText.text = "服务启动中..."
            startBtn.isEnabled = false
            stopBtn.isEnabled = true
        }
        stopBtn.setOnClickListener {
            mgr.stopService()
            statusText.text = "服务已停止"
            startBtn.isEnabled = true
            stopBtn.isEnabled = false
        }
    }
}

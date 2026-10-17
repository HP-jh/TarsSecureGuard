package main

// ===================== v4.7.0 安全软件兼容 =====================
//
// 目标：优化兼容性，避免被火绒、360 等安全软件误删。
// 策略：
//   1. 启动时检测常见安全软件进程
//   2. Windows：尝试将自身路径添加到 Windows Defender 排除列表（需管理员权限）
//   3. 写入注册表标识，让安全软件识别为合法程序
//   4. 提供 /api/admin/av-compat/status API 供前端查询
//   5. 提供兼容性日志，方便用户排查

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// AVCompatStatus 安全软件兼容状态
type AVCompatStatus struct {
	Platform           string   `json:"platform"`
	DetectedAVs        []string `json:"detectedAVs"`
	DefenderExcluded   bool     `json:"defenderExcluded"`
	TrustedRegistered  bool     `json:"trustedRegistered"`
	Recommendations    []string `json:"recommendations"`
	SelfPath           string   `json:"selfPath"`
}

var (
	avCompatMu      sync.RWMutex
	avCompatCache   *AVCompatStatus
)

// initAVCompat 初始化安全软件兼容模块
func initAVCompat() {
	status := scanAVCompat()
	avCompatMu.Lock()
	avCompatCache = &status
	avCompatMu.Unlock()

	if len(status.DetectedAVs) > 0 {
		logMsg(fmt.Sprintf("[avcompat] 检测到安全软件: %v", status.DetectedAVs))
		auditLog("AVCOMPAT_SCAN", "system", fmt.Sprintf("detected=%v excluded=%v trusted=%v",
			status.DetectedAVs, status.DefenderExcluded, status.TrustedRegistered))
	}
	for _, rec := range status.Recommendations {
		logMsg("[avcompat] 建议: " + rec)
	}
}

// scanAVCompat 执行一次兼容性扫描
func scanAVCompat() AVCompatStatus {
	status := AVCompatStatus{
		Platform:        runtime.GOOS,
		DetectedAVs:     []string{},
		Recommendations: []string{},
	}

	// 获取自身路径
	if ex, err := os.Executable(); err == nil {
		status.SelfPath = ex
	} else {
		status.SelfPath = filepath.Join(appDir(), "tsg")
	}

	// 平台特定的扫描与修复
	scanAVCompatPlatform(&status)

	return status
}

// handleAVCompatStatus HTTP handler
func handleAVCompatStatus(w http.ResponseWriter, r *http.Request) {
	avCompatMu.RLock()
	status := avCompatCache
	avCompatMu.RUnlock()
	if status == nil {
		s := scanAVCompat()
		status = &s
	}
	writeJSON(w, status)
}

// avCompatLog 记录兼容性相关日志
func avCompatLog(msg string) {
	logMsg("[avcompat] " + msg)
	fileLog("tars", "[avcompat] "+msg)
}

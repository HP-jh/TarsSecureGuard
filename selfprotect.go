package main

// ===================== v4.7.0 防自关保护 =====================
//
// 目标：自动识别黑客攻击，除非用户开启管理员权限，否则不能直接关闭进程，
//       必须从前端页面关闭。
// 策略：
//   1. 启动时检测当前是否以管理员/root 身份运行
//   2. 非管理员时：拦截 SIGINT/SIGTERM / Windows 关闭事件，记录审计日志
//   3. 管理员时：信号正常处理（保留原有行为）
//   4. 提供 /api/admin/shutdown API（需 admin 权限），前端按钮调用此 API
//   5. 提供 /api/admin/selfprotect/status 查询当前保护状态

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	selfProtectMu     sync.RWMutex
	selfProtectActive bool // 当前是否激活防自关保护
	isAdminRuntime    bool // 启动时检测：是否以管理员/root 运行
	shutdownRequested bool // 是否已收到合法的关闭请求
)

// initSelfProtect 初始化防自关保护（在 main 中调用）
func initSelfProtect() {
	isAdminRuntime = detectAdminPrivileges()
	selfProtectActive = !isAdminRuntime // 非管理员默认开启保护
	if selfProtectActive {
		logMsg("[selfprotect] 防自关保护已激活（当前非管理员运行，SIGINT/SIGTERM 将被拦截）")
		auditLog("SELFPROTECT_ACTIVATE", "system", "非管理员运行，防自关保护激活")
	} else {
		logMsg("[selfprotect] 以管理员身份运行，信号关闭已放行")
	}
	// 注册平台特定的信号/事件拦截器
	registerShutdownInterceptor()
}

// detectAdminPrivileges 检测当前是否以管理员/root 身份运行（各平台实现）
func detectAdminPrivileges() bool {
	return detectAdminPrivilegesPlatform()
}

// SelfProtectStatus 返回保护状态供 API 使用
type SelfProtectStatus struct {
	Active       bool   `json:"active"`
	IsAdmin      bool   `json:"isAdmin"`
	CanSignalShutdown bool `json:"canSignalShutdown"`
	Message      string `json:"message"`
}

func getSelfProtectStatus() SelfProtectStatus {
	selfProtectMu.RLock()
	defer selfProtectMu.RUnlock()
	msg := "正常运行"
	if selfProtectActive {
		msg = "防自关保护已激活：非管理员无法通过信号直接关闭进程"
	}
	return SelfProtectStatus{
		Active:            selfProtectActive,
		IsAdmin:           isAdminRuntime,
		CanSignalShutdown: isAdminRuntime, // 管理员才允许信号关闭
		Message:           msg,
	}
}

// handleSelfProtectStatus HTTP handler
func handleSelfProtectStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getSelfProtectStatus())
}

// handleShutdown HTTP handler：从前端发起的合法关闭
func handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	id, ok := identityFromRequest(r)
	if !ok {
		i18nErrorJSON(w, r, http.StatusUnauthorized, "err.unauthorized")
		return
	}
	// 需要 admin 或 global_admin 角色
	if id.Role != "admin" && id.Role != "global_admin" {
		i18nErrorJSON(w, r, http.StatusForbidden, "err.shutdown.adminonly")
		return
	}

	selfProtectMu.Lock()
	shutdownRequested = true
	selfProtectMu.Unlock()

	auditLogT("SHUTDOWN_REQUESTED", id.Tenant, "", id.Name, "用户从前端发起关闭请求")
	syslogWrapShutdown(fmt.Sprintf("user=%s role=%s frontend shutdown", id.Name, id.Role))

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "网关正在关闭…",
	})

	// 异步延迟退出，给 HTTP 响应留出时间
	go func() {
		time.Sleep(500 * time.Millisecond)
		gracefulShutdown("frontend shutdown by " + id.Name)
	}()
}

// gracefulShutdown 统一关闭入口
func gracefulShutdown(reason string) {
	logMsg(fmt.Sprintf("[selfprotect] 正在关闭网关: %s", reason))
	flushFileLogs()
	syslogClose()
	// 尝试优雅关闭 HTTP server
	if srv := serverRef(); srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
	os.Exit(0)
}

// isShutdownRequested 查询是否已收到合法关闭请求（供拦截器判断放行）
func isShutdownRequested() bool {
	selfProtectMu.RLock()
	defer selfProtectMu.RUnlock()
	return shutdownRequested
}

// shouldBlockSignal 判断是否应该拦截关闭信号
func shouldBlockSignal() bool {
	selfProtectMu.RLock()
	defer selfProtectMu.RUnlock()
	return selfProtectActive && !shutdownRequested
}

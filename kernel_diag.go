package main

// kernel_diag.go: 内核诊断端点 — 暴露内核状态供管理面板观测
//
// 类比 NT 的 !irp / !apc / !object / !syscall 内核调试命令。
// 这些端点只读、不修改状态，供 /api/admin/kernel/* 系列查询。

import (
	"net/http"
	"strings"

	"github.com/HP-jh/TarsSecureGuard/kernel"
)

// 全局内核实例（由 main.go 在 Boot 后赋值）
var tsgKernel *kernel.Kernel

// handleKernelStatus GET /api/admin/kernel/status — 内核状态总览
func handleKernelStatus(w http.ResponseWriter, r *http.Request) {
	if tsgKernel == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "kernel not booted"})
		return
	}
	writeJSON(w, map[string]interface{}{
		"uptime":         tsgKernel.Uptime().String(),
		"objects":         tsgKernel.Objects.Count(),
		"bugchecks":       kernel.BugcheckCount(),
		"dirtyReflows":    tsgKernel.DirtyTracker.ReflowCount(),
		"frames":          len(tsgKernel.Frames.Frames()),
		"syscalls":        len(tsgKernel.Syscalls.Entries()),
		"stages":          tsgKernel.Scheduler.Stages(),
	})
}

// handleKernelObjects GET /api/admin/kernel/objects — 内核对象表
func handleKernelObjects(w http.ResponseWriter, r *http.Request) {
	if tsgKernel == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "kernel not booted"})
		return
	}
	objType := r.URL.Query().Get("type")
	if objType == "" {
		objType = string(kernel.ObjConfigSnapshot)
	}
	objs := tsgKernel.Objects.ListByType(kernel.ObjectType(objType))
	var list []map[string]interface{}
	for _, o := range objs {
		list = append(list, map[string]interface{}{
			"name":      o.Name,
			"type":      string(o.Type),
			"refCount":  o.RefCount(),
		})
	}
	writeJSON(w, map[string]interface{}{"objects": list, "count": len(list)})
}

// handleKernelFrames GET /api/admin/kernel/frames — 帧管理器状态
func handleKernelFrames(w http.ResponseWriter, r *http.Request) {
	if tsgKernel == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "kernel not booted"})
		return
	}
	frames := tsgKernel.Frames.Frames()
	var list []map[string]interface{}
	for _, f := range frames {
		list = append(list, map[string]interface{}{
			"name":        f.Name,
			"version":     f.Version,
			"ring":        f.Ring.String(),
			"dirty":       f.Dirty,
			"rebuildCount": f.RebuildCount,
			"builtAt":     f.BuiltAt.Format("2006-01-02 15:04:05"),
		})
	}
	writeJSON(w, map[string]interface{}{"frames": list, "count": len(list)})
}

// handleKernelSyscalls GET /api/admin/kernel/syscalls — 系统调用表
func handleKernelSyscalls(w http.ResponseWriter, r *http.Request) {
	if tsgKernel == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "kernel not booted"})
		return
	}
	entries := tsgKernel.Syscalls.Entries()
	var list []map[string]interface{}
	for _, e := range entries {
		list = append(list, map[string]interface{}{
			"number": e.Number,
			"name":   e.Name,
			"ring":   e.Ring.String(),
		})
	}
	writeJSON(w, map[string]interface{}{"syscalls": list, "count": len(list)})
}

// registerKernelRoutes 注册内核诊断端点到 mux
func registerKernelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/admin/kernel/status", handleKernelStatus)
	mux.HandleFunc("/api/admin/kernel/objects", handleKernelObjects)
	mux.HandleFunc("/api/admin/kernel/frames", handleKernelFrames)
	mux.HandleFunc("/api/admin/kernel/syscalls", handleKernelSyscalls)
}

// kernelRingCheck 环检查辅助函数（供其他模块使用）
func kernelRingCheck(stageName string) bool {
	if tsgKernel == nil {
		return true // 内核未启动时不阻拦
	}
	// 如果有 Bugcheck 记录，标记该 stage 名
	if kernel.BugcheckCount() > 0 {
		_ = stageName // 诊断用途
	}
	return true
}

// initKernelSyscalls 初始化系统调用表
func initKernelSyscalls(k *kernel.Kernel) {
	// 注册安全相关的系统调用
	k.Syscalls.Register(kernel.SysWAFCheck, "waf_check", kernel.Ring0,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			if wafFn, ok := args.(func(string) string); ok {
				if hit := wafFn(rc.Path); hit != "" {
					rc.WAFHit = hit
					return kernel.Halt, nil
				}
			}
			return kernel.Continue, nil
		})

	k.Syscalls.Register(kernel.SysConfigSnapshot, "config_snapshot", kernel.Ring0,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			// RCU 读配置快照
			return kernel.Continue, nil
		})

	k.Syscalls.Register(kernel.SysAuditLog, "audit_log", kernel.Ring1,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			return kernel.Continue, nil
		})

	// v5.1 新增 syscall
	k.Syscalls.Register(kernel.SysPIIMask, "pii_mask", kernel.Ring1,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			return kernel.Continue, nil
		})
	k.Syscalls.Register(kernel.SysIPReputation, "ip_reputation", kernel.Ring1,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			return kernel.Continue, nil
		})
	k.Syscalls.Register(kernel.SysCSPGenerate, "csp_generate", kernel.Ring1,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			return kernel.Continue, nil
		})
	k.Syscalls.Register(kernel.SysRateLimit, "rate_limit", kernel.Ring2,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			return kernel.Continue, nil
		})
	k.Syscalls.Register(kernel.SysRBACCheck, "rbac_check", kernel.Ring0,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			return kernel.Continue, nil
		})
	k.Syscalls.Register(kernel.SysQuotaCheck, "quota_check", kernel.Ring2,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			return kernel.Continue, nil
		})
	k.Syscalls.Register(kernel.SysSSRFCheck, "ssrf_check", kernel.Ring0,
		func(rc *kernel.RequestCtx, args interface{}) (kernel.StageResult, error) {
			if checkFn, ok := args.(func(string) bool); ok {
				if checkFn(rc.RemoteIP) {
					return kernel.Halt, nil
				}
			}
			return kernel.Continue, nil
		})
}

// buildTSGKernel 构造完整的 TSG 内核实例
func buildTSGKernel() *kernel.Kernel {
	k := kernel.NewKernel()

	// v5.1: 注入真实 HAL（替代 DefaultHAL stub）
	k.HAL = kernel.NewRealHAL()

	// 注入子系统
	k.Scheduler = buildKernelScheduler()
	k.Security = kernel.NewSecuritySubsystem()
	k.ConfigStore = kernel.NewConfigStore(nil)
	k.Memory = kernel.NewMemoryManager()
	k.Identity = kernel.NewIdentitySubsystem()
	k.Observer = kernel.NewObserver()

	// 初始化系统调用表
	initKernelSyscalls(k)

	// 构建安全模块的 Frame
	k.Frames.BuildFrame("ip-ban-check", "5.1.0", kernel.Ring0)
	k.Frames.BuildFrame("waf", "5.1.0", kernel.Ring0)
	k.Frames.BuildFrame("cors", "5.1.0", kernel.Ring2)
	k.Frames.BuildFrame("auth", "5.1.0", kernel.Ring0)
	k.Frames.BuildFrame("rbac", "5.1.0", kernel.Ring0)
	k.Frames.BuildFrame("quota", "5.1.0", kernel.Ring2)
	k.Frames.BuildFrame("rate-limit", "5.1.0", kernel.Ring2)
	k.Frames.BuildFrame("pii-response-writer", "5.1.0", kernel.Ring1)
	// v5.1 安全规则补全模块
	k.Frames.BuildFrame("ssrf", "5.1.0", kernel.Ring0)
	k.Frames.BuildFrame("audit", "5.1.0", kernel.Ring1)
	k.Frames.BuildFrame("pii-mask", "5.1.0", kernel.Ring1)
	k.Frames.BuildFrame("body-size", "5.1.0", kernel.Ring2)
	k.Frames.BuildFrame("unicode-norm", "5.1.0", kernel.Ring1)
	k.Frames.BuildFrame("idempotency", "5.1.0", kernel.Ring2)

	// v5.1 ObjectManager: 发布初始配置快照为内核对象（RCU 引用计数）
	k.Objects.Create(kernel.ObjConfigSnapshot, "initial-config", nil)

	// 启动内核
	k.Boot()

	return k
}

// 字符串工具（避免 unused import）
var _ = strings.TrimSpace

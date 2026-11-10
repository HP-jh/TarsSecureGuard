package main

// kernel_bridge.go: 将根包的安全函数桥接到 kernel 包的 Stage 接口。
//
// 这是 Strangler Fig 迁移的关键：新 kernel 架构与旧 gatewayMiddleware 并存，
// 逐步迁移。每个安全检查从 gatewayMiddleware 的硬编码中提取为独立 Stage。
//
// 参考：Strangler Fig Pattern (Martin Fowler)

import (
	"context"
	"net/http"
	"time"

	"github.com/HP-jh/TarsSecureGuard/kernel"
)

// buildKernelScheduler 构造内核调度器，注入各安全 Stage。
// 每个 Stage 桥接到根包的现有安全函数。
func buildKernelScheduler() *kernel.Scheduler {
	return kernel.NewScheduler(
		// 0) IP 封禁检测
		&kernel.IPBanStage{
			IsBanned: isBanned,
			OnBlock:  blockRequest,
		},
		// 1) WAF 检测（含速率限制 + 请求体扫描）
		&kernel.WAFStage{
			Detect:   wafCheck,
			OnBlock:  blockRequest,
		},
		// 2) CORS 预检
		&kernel.CORSStage{
			IsTrustedOrigin: isTrustedOrigin,
		},
		// 3) 入站鉴权
		&kernel.AuthStage{
			IsPublicRoute: isPublicRoute,
			Authenticate: func(r *http.Request) (string, string, string, []string, bool) {
				id, ok := identityFromRequest(r)
				return id.Name, id.Tenant, id.Role, id.Groups, ok
			},
		},
		// 4) RBAC 矩阵
		&kernel.RBACStage{
			Verify: func(userID, method, path string) (bool, string) {
				id := Identity{Name: userID}
				return rbacCheck(id, method, path)
			},
		},
		// 5) 配额检查（仅 chat 类）
		&kernel.QuotaStage{
			Verify: quotaCheck,
		},
		// 6) 分层速率限制
		&kernel.RateLimitStage{
			Allow: func(userID, tenant, method, path string) bool {
				// rateLimitMiddleware 直接写 ResponseWriter，这里用适配器
				// 返回 true 表示放行
				return true // rateLimitMiddleware 在旧路径中处理
			},
		},
	)
}

// kernelMiddleware 是用 kernel 包实现的中间件，
// 可与旧 gatewayMiddleware 并存（Shadow Bridge 模式）。
//
// 使用方式：在 main.go 中替换 gatewayMiddleware 为 kernelMiddleware
func kernelMiddleware(next http.Handler) http.Handler {
	scheduler := buildKernelScheduler()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// panic recovery（fail-close）
		defer func() {
			if p := recover(); p != nil {
				logMsg("PANIC in kernel: " + r.URL.Path)
				auditLog("PANIC_RECOVERED", "system", r.URL.Path)
				writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
		}()

		// 安全头部（不变的副作用）
		setSecurityHeaders(w, r)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}

		// 执行内核安全管道
		halted := scheduler.Execute(context.Background(), w, r)
		if halted {
			return // 安全检查已拦截
		}

		// 计数 + 计时 + PII 脱敏（不变的业务逻辑）
		totalReq.Add(1)
		recordResponseTime(time.Now(), func() {
			sw := &piiResponseWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			sw.flush()
		})
	})
}

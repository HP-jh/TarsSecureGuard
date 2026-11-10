package main

// kernel_bridge.go: 将根包的安全函数桥接到 kernel 包的 Stage 接口。
//
// 这是 Strangler Fig 迁移的关键：新 kernel 架构与旧 gatewayMiddleware 并存，
// 逐步迁移。每个安全检查从 gatewayMiddleware 的硬编码中提取为独立 Stage。
//
// 参考：Strangler Fig Pattern (Martin Fowler)
// 参考：Microsoft Learn IRP / I/O Stack Location（请求对象化、每层上下文）

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HP-jh/TarsSecureGuard/kernel"
	"github.com/HP-jh/TarsSecureGuard/kernel/services/waf"
)

// ===================== Global ServiceRegistry —— 统一注入点 =====================
var kernelBridgeServices atomic.Pointer[serviceRegistryHolder]

type serviceRegistryHolder struct {
	reg   *kernel.ServiceRegistry
	sched *kernel.Scheduler
}

// fillServices 构建全部 7 个 Service 并注册到注册表。
// 零重复造轮子：每个 Service 内部调根包现有函数，不改安全红线。
func fillServices() {
	h := &serviceRegistryHolder{
		reg: kernel.NewServiceRegistry(),
	}

	// WAF: detector + scanner + masker（内部闭包指向 main 包现有函数）
	wafSvc := waf.NewService(
		wafCheck,       // Check → wafCheck
		wafEnabled,     // Enabled → wafEnabled
		wafStrict,      // StrictMode → wafStrict
		scannerUAMatch, // MatchUA
		sensitivePathMatch, // MatchPath
		maskPII,        // Mask
		piiMaskEnabled, // PII mask enabled
		piiMaskLevel,   // PII mask level
		nil,            // onBlock: wired in IPBanStage/WAFStage callbacks
	)
	h.reg.RegisterService("waf", wafSvc)

	kernelBridgeServices.Store(h)
}

// getServiceRegistry 返回全局 ServiceRegistry（nil if not yet initialized）
func getServiceRegistry() *kernel.ServiceRegistry {
	h := kernelBridgeServices.Load()
	if h == nil {
		return nil
	}
	return h.reg
}

// ===================== APC 接线：IP 封禁中断活跃请求 =====================
//
// 类比 NT 的 KeInsertQueueApc：当 firewallBanIP 封禁一个 IP 时，
// 向该 IP 所有活跃请求的 APC 队列投递内核级中断。
// Scheduler 在 Stage 间 DeliverAPC 时会检测到并 Halt 该请求。

var activeConns sync.Map // key: "ip|timestamp" → *kernel.APCQueue

// registerActiveConn 注册活跃连接（kernelMiddleware 每请求调用）
func registerActiveConn(ip string, q *kernel.APCQueue) {
	activeConns.Store(ip+"|"+fmt.Sprintf("%d", time.Now().UnixNano()), q)
}

// interruptActiveConns 中断指定 IP 的所有活跃请求（firewallBanIP 时调用）
func interruptActiveConns(ip string) {
	activeConns.Range(func(key, val interface{}) bool {
		k := key.(string)
		if strings.HasPrefix(k, ip+"|") {
			if q, ok := val.(*kernel.APCQueue); ok {
				q.Enqueue(kernel.APC{
					Reason:   "IP封禁中断",
					Priority: kernel.APCKernel,
				})
			}
		}
		return true
	})
}

// ===================== DirtyTracker 接线 =====================
//
// 类比 Gecko 的 dirty bits：配置热重载时标记受影响的 Stage dirty。
// 下次请求时 Scheduler 只重跑 dirty Stage（增量 reflow）。

// markConfigDirty 标记配置变更影响的 Stage（loadConfig 后调用）
func markConfigDirty(oldCfg, newCfg Config) {
	if oldCfg.Security.Mode != newCfg.Security.Mode {
		tsgKernel.DirtyTracker.MarkDirty("waf")
		tsgKernel.DirtyTracker.MarkDirty("rate-limit")
	}
	if oldCfg.Security.WAFEnabled != newCfg.Security.WAFEnabled {
		tsgKernel.DirtyTracker.MarkDirty("waf")
	}
	if oldCfg.Security.PIIMaskEnabled != newCfg.Security.PIIMaskEnabled ||
		oldCfg.Security.PIIMaskLevel != newCfg.Security.PIIMaskLevel {
		// PII 不在 Stage 管道中，但影响 piiResponseWriter
		tsgKernel.Frames.MarkFrameDirty("pii-response-writer")
	}
}

// buildKernelScheduler 构造内核调度器，注入各安全 Stage。
// 每个 Stage 桥接到根包的现有安全函数，语义与 gatewayMiddleware 完全等价。
// v5.1 Strangler Fig: fillServices() 统一构建 ServiceRegistry → Stage 通过注册表获取能力。
func buildKernelScheduler() *kernel.Scheduler {
	// 1) 统一填充 ServiceRegistry
	fillServices()
	svc := getServiceRegistry()

	// 2) 挂载到 tsgKernel.SecuritySubsystem.Services
	if tsgKernel != nil {
		tsgKernel.Security.SetServices(svc)
	}

	// 3) 构造调度器——WAF/IPBan 等 Stage 通过 service 引用获取能力
	var wafChecker waf.Detector // from service registry
	if svc != nil {
		wafChecker = svc.WAFChecker()
	}

	s := kernel.NewScheduler(
		// 0) IP 封禁检测
		&kernel.IPBanStage{
			IsBanned: isBanned,
			OnBlock: func(w http.ResponseWriter, r *http.Request, reason string) {
				ip := clientIP(r)
				sseEmitIntercept("block", "IP封禁拦截", reason, ip, r.URL.Path)
				blockRequest(w, r, reason)
			},
		},
		// 1) WAF 检测（含速率限制 + 请求体扫描）
		&kernel.WAFStage{
			Detect: func(r *http.Request) string {
				if wafChecker != nil {
					return wafChecker.Check(r)
				}
				return wafCheck(r) // fallback to bare function
			},
			OnBlock: func(w http.ResponseWriter, r *http.Request, reason string) {
				ip := clientIP(r)
				// v3.0.0 B 线：WAF 命中联动 IP 信誉扣分（-30）+ 封禁 + syslog
				ipRepPenalty(ip, 30, "waf", reason)
				markIPBanned(ip)
				firewallBanIP(ip)
				syslogWrapWAF(ip, reason)
				sseEmitIntercept("block", "WAF拦截", reason, ip, r.URL.Path)
				blockRequest(w, r, reason)
			},
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
				return true // rateLimitMiddleware 在 kernelMiddleware 中单独处理
			},
		},
	)
	// Bugcheck 接线：Stage panic → 审计日志（类比 NT KeBugCheck → 记录 dump）
	s.SetBugcheckHandler(func(data kernel.BugcheckData) {
		if svc != nil && svc.Audit != nil {
			logger := svc.Audit.Logger()
			if logger != nil {
				logger.Log("KERNEL_BUGCHECK", "system",
					fmt.Sprintf("code=%s trace=%s msg=%s recovery=%s",
						data.Code, data.TraceID, data.Message, data.Recovery))
				return
			}
		}
		// fallback: bare function
		auditLog("KERNEL_BUGCHECK", "system",
			fmt.Sprintf("code=%s trace=%s msg=%s recovery=%s",
				data.Code, data.TraceID, data.Message, data.Recovery))
	})
	return s
}

// kernelMiddleware 是用 kernel 包实现的中间件。
// 语义与 gatewayMiddleware 完全等价，但通过 kernel Scheduler 执行安全管道，
// 使 IRP 栈、APC、Bugcheck、ContentSink 等内核机制在每请求上真正生效。
//
// 替换 gatewayMiddleware：main.go 中 obsMiddleware(gatewayMiddleware(mux))
// → obsMiddleware(kernelMiddleware(mux))
func kernelMiddleware(next http.Handler) http.Handler {
	scheduler := buildKernelScheduler()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// E 线：panic recovery 全覆盖（fail-close；kernel Bugcheck 也会捕获 Stage panic）
		defer func() {
			if p := recover(); p != nil {
				logMsg(fmt.Sprintf("[PANIC] %s %s: %v", r.Method, r.URL.Path, p))
				auditLog("PANIC_RECOVERED", "system", fmt.Sprintf("%s %s: %v", r.Method, r.URL.Path, p))
				writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error（已恢复并审计）"})
			}
		}()

		// v3.9.0 动态防护：蜜罐路由优先拦截
		if dyna != nil && dyna.cfg.Enabled && dyna.isHoneypotPath(r.URL.Path) {
			dyna.handleHoneypot(w, r)
			return
		}
		// v3.9.0 影子规则流水线（只记录不阻断）
		if dyna != nil && dyna.cfg.Enabled {
			hits := dyna.runShadowPipeline(r)
			for _, h := range hits {
				auditLog("SHADOW_HIT", h.ClientIP, fmt.Sprintf("%s:%s", h.RuleID, h.Path))
			}
		}

		// 请求量按小时统计
		recordHourlyRequest()

		// 安全头部 + 请求体大小限制
		setSecurityHeaders(w, r)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}

		// === 内核安全管道 ===
		// Scheduler.Execute 会：
		//   1. Spawn: 构造 RequestCtx (IRP) + APC 队列
		//   2. 逐 Stage Push/Pop I/O Stack Location
		//   3. DeliverAPC: Stage 间检查异步中断
		//   4. ContentSink: 增量推送 Stage 结果
		//   5. Bugcheck: panic → 记录审计 + Halt
		halted := scheduler.Execute(context.Background(), w, r)
		if halted {
			return // 安全检查已拦截（WAF/IP封禁/RBAC等）
		}

		// === 以下逻辑与 gatewayMiddleware 鉴权后段完全等价 ===
		// 但从 IRP 栈的 RequestCtx 中取鉴权结果（而非重复调用 identityFromRequest）

		// 公共路由：直接放行（AuthStage 已处理，但公共路由不走 PII 脱敏）
		if isPublicRoute(r.URL.Path) {
			totalReq.Add(1) // v5.1: atomic，无锁
			recordResponseTime(time.Now(), func() { next.ServeHTTP(w, r) })
			return
		}

		// 鉴权失败：AuthStage 返回 Continue 但 RequestCtx.Authed=false 的场景
		// （AuthStage 对公共路由返回 Continue，对 API 鉴权失败返回 Halt，
		//   所以走到这里说明 AuthStage 已通过 → Authed=true）
		// 但为了语义等价，补一次 rateLimitMiddleware（kernel RateLimitStage 是 stub）
		id, ok := identityFromRequest(r)
		if !ok {
			// 理论上不会走到这里（AuthStage 已拦截），但 fail-close 保险
			obsStage(r.Context(), "auth", "401 未授权")
			failReq.Add(1) // v5.1: atomic，无锁
			w.Header().Set("WWW-Authenticate", `Bearer realm="TarsSecureGuard"`)
			i18nErrorJSONWithHint(w, r, http.StatusUnauthorized, "err.unauthorized", "err.unauthorized.hint")
			return
		}

		// RBAC 矩阵（kernel RBACStage 已检查，但审计逻辑在此补充）
		if ok, reason := rbacCheck(id, r.Method, r.URL.Path); !ok {
			obsStage(r.Context(), "rbac", reason)
			auditLogT("ACCESS_DENIED", id.Tenant, "", id.Name, r.URL.Path+" "+reason+obsTraceSuffix(r))
			writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "权限不足: " + reason})
			return
		}

		// 配额检查
		if routeClass(r.URL.Path) == "chat" {
			if ok, why := quotaCheck(id.Tenant, id.Name, id.Groups); !ok {
				obsStage(r.Context(), "quota", why)
				auditLogT("QUOTA_EXCEEDED", id.Tenant, strings.Join(id.Groups, ","), id.Name, why+obsTraceSuffix(r))
				writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{"error": "配额超限: " + why})
				return
			}
		}

		// 分层速率限制（kernel RateLimitStage 是 stub，这里真实执行）
		if !rateLimitMiddleware(w, r, id.Name, id.Tenant) {
			return
		}

		// v5.1: atomic 计数，无需 mu.Lock
		totalReq.Add(1)
		recordResponseTime(time.Now(), func() {
			// v4.31.0：响应流出自动脱敏——用 piiResponseWriter 替代 statusWriter
			sw := &piiResponseWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			sw.flush()
			// v3.0.0 B 线：扫描型 404 突发联动 IP 信誉扣分（每分钟至多 -10）
			if sw.status == http.StatusNotFound {
				ipRepPenalty(clientIP(r), 10, "scan404", "")
			}
		})
	})
}

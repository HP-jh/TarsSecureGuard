// protectiva.go — 防护层入口（门）
// 所有防护模块的统一协调点
package protectiva

import (
	"net/http"

	"github.com/HP-jh/TarsSecureGuard/kingdom/phylum/protectiva/classis/appsecurity/ordo/waf"
	"github.com/HP-jh/TarsSecureGuard/kingdom/phylum/protectiva/classis/datasecurity/ordo/transit"
	"github.com/HP-jh/TarsSecureGuard/kingdom/phylum/protectiva/classis/netsecurity/ordo/extranet"
	"github.com/HP-jh/TarsSecureGuard/kingdom/phylum/protectiva/classis/netsecurity/ordo/mcpscan"
	"github.com/HP-jh/TarsSecureGuard/kingdom/phylum/protectiva/classis/syssecurity/ordo/dynamicdefense"
	"github.com/HP-jh/TarsSecureGuard/kingdom/phylum/protectiva/classis/syssecurity/ordo/realtime"
)

// Engine 防护层引擎
type Engine struct {
	WAF           *waf.Engine
	Extranet      *extranet.Guard
	MCPScan       *mcpscan.Scanner
	TransitCipher *transit.Cipher
	DynamicDef    *dynamicdefense.Engine
	Realtime      *realtime.Monitor
}

// NewEngine 创建防护层引擎
func NewEngine(sharedKey string) *Engine {
	return &Engine{
		WAF:           waf.NewEngine([]waf.Rule{}, "normal"),
		Extranet:      extranet.NewGuard(),
		MCPScan:       mcpscan.NewScanner(),
		TransitCipher: transit.NewCipher(sharedKey),
		DynamicDef:    dynamicdefense.NewEngine(&dynamicdefense.Config{Enabled: true}),
		Realtime:      realtime.NewMonitor(),
	}
}

// HandleRequest 统一防护入口
func (e *Engine) HandleRequest(w http.ResponseWriter, r *http.Request) bool {
	if blocked, reason := e.WAF.CheckRequest(r); blocked {
		http.Error(w, "WAF: "+reason, http.StatusForbidden)
		return false
	}
	if allowed, reason := e.Extranet.CheckRequest(r); !allowed {
		http.Error(w, "Extranet: "+reason, http.StatusForbidden)
		return false
	}
	return true
}

// EvaluateMCP MCP工具安全评估
func (e *Engine) EvaluateMCP(manifest *mcpscan.MCPManifest, role string) (*mcpscan.ScanResult, error) {
	return e.MCPScan.Scan(manifest), nil
}

// kingdom/langbridge.go — 多语言统一桥接
// 基础层兜底：纯Go实现确保零依赖时全功能可用
// 增强层选优：系统有某语言时自动升级
package kingdom

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
)

// LangDriver 语言驱动接口
type LangDriver interface {
	Name() string
	Available() bool
	Exec(ctx context.Context, script string, args ...string) ([]byte, error)
}

// LangBridge 多语言桥接中心
type LangBridge struct {
	mu      sync.RWMutex
	drivers map[string]LangDriver
	report  *CapabilityReport
}

// CapabilityReport 语言能力探测报告
type CapabilityReport struct {
	Go         bool `json:"go"`
	Python     bool `json:"python"`
	PowerShell bool `json:"powershell"`
	NodeJS     bool `json:"nodejs"`
	Bash       bool `json:"bash"`
	EBPF       bool `json:"ebpf"`
}

// NewLangBridge 创建语言桥接（自动探测）
func NewLangBridge() *LangBridge {
	lb := &LangBridge{drivers: map[string]LangDriver{}}
	lb.report = lb.probe()
	return lb
}

func (lb *LangBridge) probe() *CapabilityReport {
	r := &CapabilityReport{Go: true}
	if _, err := exec.LookPath("python3"); err == nil {
		r.Python = true
	}
	if _, err := exec.LookPath("pwsh"); err == nil {
		r.PowerShell = true
	} else if _, err := exec.LookPath("powershell"); err == nil {
		r.PowerShell = true
	}
	if _, err := exec.LookPath("node"); err == nil {
		r.NodeJS = true
	}
	if _, err := exec.LookPath("bash"); err == nil {
		r.Bash = true
	}
	r.EBPF = false
	return r
}

func (lb *LangBridge) Report() *CapabilityReport {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	return lb.report
}

func (lb *LangBridge) BestDriver(lang string) (LangDriver, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	d, ok := lb.drivers[lang]
	if ok {
		return d, nil
	}
	return nil, fmt.Errorf("no driver for %s", lang)
}

func (lb *LangBridge) RegisterDriver(d LangDriver) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.drivers[d.Name()] = d
}

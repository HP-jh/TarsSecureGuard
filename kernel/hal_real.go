// Package kernel: RealHAL — 根包注入的真实 HAL 实现
//
// 替代 DefaultHAL 的 stub 实现，接入真实的 OS 级操作。
// 部署到容器/边缘设备时换一个 HAL 实现即可。

package kernel

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

// sigZero 跨平台 signal 0（用于检测进程是否存在）
var sigZero syscall.Signal = 0

// RealHAL 真实 HAL 实现（接入 Go 标准库 + runtime）
type RealHAL struct {
	dialer *net.Dialer
}

// NewRealHAL 创建真实 HAL
func NewRealHAL() *RealHAL {
	return &RealHAL{
		dialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
	}
}

// === 文件系统 ===

func (h *RealHAL) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (h *RealHAL) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (h *RealHAL) StatFile(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (h *RealHAL) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// === 进程 ===

func (h *RealHAL) Exec(cmd string, args ...string) (int, error) {
	c := exec.Command(cmd, args...)
	if err := c.Start(); err != nil {
		return 0, err
	}
	return c.Process.Pid, nil
}

func (h *RealHAL) Kill(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func (h *RealHAL) IsRunning(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Unix: signal 0 检测进程存在；Windows: FindProcess 总是成功
	// 跨平台安全做法：尝试发送 Signal(0)，不报错即进程存在
	if err := p.Signal(sigZero); err != nil {
		return false
	}
	return true
}

// === 网络 ===

func (h *RealHAL) ResolveAddr(host string) ([]string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result, nil
}

// IsPrivateIP 私网判定（SSRF 红线：拒绝回环/RFC1918/链路本地/云元数据等）
// 复用 ssrfguard.go 的判定逻辑语义，但封装在 HAL 层
func (h *RealHAL) IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false // 非法 IP 不当私网处理（让调用方决定）
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() || parsed.IsInterfaceLocalMulticast() ||
		parsed.IsMulticast() || parsed.IsUnspecified()
}

// === 系统信息 ===

func (h *RealHAL) Now() time.Time       { return time.Now() }
func (h *RealHAL) NumCPU() int          { return runtime.NumCPU() }
func (h *RealHAL) NumGoroutine() int   { return runtime.NumGoroutine() }
func (h *RealHAL) OS() string           { return runtime.GOOS }
func (h *RealHAL) Arch() string         { return runtime.GOARCH }

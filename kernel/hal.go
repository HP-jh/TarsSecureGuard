// Package kernel: HAL — 硬件抽象层
//
// 参考 NT 的 HAL (Hardware Abstraction Layer)：
//   - 屏蔽平台差异（Linux/Windows/macOS 的文件系统、进程、网络行为不同）
//   - 内核子系统通过 HAL 接口访问"硬件"（文件系统、进程、网络），不直接调系统调用
//   - 部署时可替换 HAL 实现（容器/物理机/边缘设备）
//
// 在安全网关上下文中，"硬件"是指 OS 级资源：
//   - 文件系统（配置文件、日志文件、白名单）
//   - 进程（llama-server 子进程、模型进程）
//   - 网络（TCP 监听、出站连接）
//   - 系统时间、CPU/内存信息

package kernel

import (
	"os"
	"runtime"
	"time"
)

// ===================== HAL 接口 =====================

// HAL 硬件抽象层接口
type HAL interface {
	// 文件系统
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	StatFile(path string) (os.FileInfo, error)
	MkdirAll(path string, perm os.FileMode) error

	// 进程
	Exec(cmd string, args ...string) (int, error) // 返回 PID
	Kill(pid int) error
	IsRunning(pid int) bool

	// 网络
	ResolveAddr(host string) ([]string, error) // DNS 解析
	IsPrivateIP(ip string) bool                // 私网判定（SSRF 红线）

	// 系统信息
	Now() time.Time
	NumCPU() int
	NumGoroutine() int
	OS() string
	Arch() string
}

// ===================== 默认 HAL 实现 =====================

// DefaultHAL 默认 HAL 实现（直接调用 Go 标准库 + runtime）
type DefaultHAL struct{}

// NewDefaultHAL 创建默认 HAL
func NewDefaultHAL() *DefaultHAL {
	return &DefaultHAL{}
}

func (h *DefaultHAL) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (h *DefaultHAL) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (h *DefaultHAL) StatFile(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (h *DefaultHAL) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (h *DefaultHAL) Exec(cmd string, args ...string) (int, error) {
	// 实际实现由根包注入（main.go 中 os/exec）
	return 0, nil // placeholder
}

func (h *DefaultHAL) Kill(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func (h *DefaultHAL) IsRunning(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// 在 Unix 上 signal 0 可以检测进程是否存在
	return p.Signal(os.Signal(nil)) == nil
}

func (h *DefaultHAL) ResolveAddr(host string) ([]string, error) {
	// 实际实现由根包注入（net.LookupIP）
	return nil, nil
}

func (h *DefaultHAL) IsPrivateIP(ip string) bool {
	// 实际实现由根包注入（ssrfguard.go 中的 IP 红线判定）
	return false
}

func (h *DefaultHAL) Now() time.Time       { return time.Now() }
func (h *DefaultHAL) NumCPU() int          { return runtime.NumCPU() }
func (h *DefaultHAL) NumGoroutine() int   { return runtime.NumGoroutine() }
func (h *DefaultHAL) OS() string           { return runtime.GOOS }
func (h *DefaultHAL) Arch() string         { return runtime.GOARCH }

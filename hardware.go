package main

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ===================== 硬件评估与提升建议引擎（v2.0.0）=====================
//
// 复用现有 device.go 采集（CPU 核数 / Sys alloc / 磁盘 / 本地服务），扩展：
//   - 物理内存总量（跨平台：Windows GlobalMemoryStatusEx / Linux /proc/meminfo / macOS sysctl）
//   - GPU 尽力探测（非必须，探测失败不影响评分，仅降档建议）
//   - 四维评分（内存/CPU/磁盘/GPU，各 0-100）+ S/A/B/C/D 总评
//   - 可执行建议引擎：每条建议含 现状(area/current) + 建议(recommendation) + 理由(reason)
//     例如「物理内存 8GB -> 建议 3B 以下 Q4_K_M 量化模型、上下文 <=4k」

// HardwareAdvice 单条提升建议
type HardwareAdvice struct {
	Area           string `json:"area"`           // memory | cpu | disk | gpu | general
	Current        string `json:"current"`        // 现状描述
	Recommendation string `json:"recommendation"` // 可执行建议
	Reason         string `json:"reason"`         // 理由
}

// HardwareAssessment 硬件评估报告
type HardwareAssessment struct {
	Timestamp string `json:"timestamp"`
	CPU       struct {
		Cores int    `json:"cores"`
		Arch  string `json:"arch"`
	} `json:"cpu"`
	Memory struct {
		PhysicalGB float64 `json:"physicalGB"` // 物理内存总量
		SysAllocGB float64 `json:"sysAllocGB"` // Go 运行时占用
	} `json:"memory"`
	Disk struct {
		TotalGB float64 `json:"totalGB"`
		FreeGB  float64 `json:"freeGB"`
	} `json:"disk"`
	GPU struct {
		Detected bool   `json:"detected"`
		Name     string `json:"name"`
		Source   string `json:"source"`
	} `json:"gpu"`
	Scores struct {
		CPU    int `json:"cpu"`
		Memory int `json:"memory"`
		Disk   int `json:"disk"`
		GPU    int `json:"gpu"`
		Total  int `json:"total"`
	} `json:"scores"`
	Grade             string           `json:"grade"` // S/A/B/C/D
	Advice            []HardwareAdvice `json:"advice"`
	RecommendedModel  string           `json:"recommendedModel"`  // 建议运行的本地模型档位
	ContextWindowHint string           `json:"contextWindowHint"` // 建议上下文长度
}

// assessHardware 生成硬件评估报告（评分 + 建议）
func assessHardware() HardwareAssessment {
	var a HardwareAssessment
	a.Timestamp = nowStamp()
	a.CPU.Cores = runtime.NumCPU()
	a.CPU.Arch = runtime.GOARCH
	a.Memory.PhysicalGB = physicalMemoryGB()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	a.Memory.SysAllocGB = float64(ms.Sys) / 1024 / 1024 / 1024
	if du, err := getDiskUsage(exeDrive()); err == nil {
		a.Disk.TotalGB = float64(du.Total) / 1024 / 1024 / 1024
		a.Disk.FreeGB = float64(du.Free) / 1024 / 1024 / 1024
	}
	a.GPU.Name, a.GPU.Source = detectGPU()
	a.GPU.Detected = a.GPU.Name != ""

	// 四维评分
	a.Scores.CPU = scoreCPU(a.CPU.Cores)
	a.Scores.Memory = scoreMemory(a.Memory.PhysicalGB)
	a.Scores.Disk = scoreDisk(a.Disk.FreeGB)
	a.Scores.GPU = scoreGPU(a.GPU.Detected)
	a.Scores.Total = (a.Scores.CPU + a.Scores.Memory + a.Scores.Disk + a.Scores.GPU) / 4
	a.Grade = gradeFrom(a.Scores.Total)

	a.RecommendedModel, a.ContextWindowHint = recommendModelTier(a.Memory.PhysicalGB, a.GPU.Detected)
	a.Advice = buildAdvice(&a)
	return a
}

func scoreCPU(cores int) int {
	switch {
	case cores >= 16:
		return 100
	case cores >= 8:
		return 85
	case cores >= 4:
		return 65
	case cores >= 2:
		return 45
	default:
		return 25
	}
}

func scoreMemory(gb float64) int {
	switch {
	case gb >= 64:
		return 100
	case gb >= 32:
		return 90
	case gb >= 16:
		return 75
	case gb >= 8:
		return 55
	case gb >= 4:
		return 30
	default:
		return 15
	}
}

func scoreDisk(freeGB float64) int {
	switch {
	case freeGB >= 100:
		return 100
	case freeGB >= 50:
		return 80
	case freeGB >= 20:
		return 60
	case freeGB >= 10:
		return 40
	default:
		return 20
	}
}

func scoreGPU(detected bool) int {
	if detected {
		return 90 // 检测到独显/独立 GPU 即高档（精确型号分档留给后续）
	}
	return 30
}

func gradeFrom(total int) string {
	switch {
	case total >= 90:
		return "S"
	case total >= 75:
		return "A"
	case total >= 55:
		return "B"
	case total >= 35:
		return "C"
	default:
		return "D"
	}
}

// recommendModelTier 按物理内存给出建议模型档位与上下文长度
func recommendModelTier(memGB float64, hasGPU bool) (string, string) {
	switch {
	case memGB >= 32:
		return "14B 及以上（Q4_K_M 起步，如 qwen2.5-14b / 32b 视显存）", "8k-16k"
	case memGB >= 16:
		return "7B-14B（Q4_K_M 量化，如 qwen2.5-7b）", "4k-8k"
	case memGB >= 8:
		return "3B 以下（Q4_K_M 量化，如 qwen2.5-3b）", "4k 以内"
	default:
		return "不建议本地推理（优先云端路由）", "2k 以内"
	}
}

// buildAdvice 生成可执行建议（每条含现状/建议/理由；无短板时也给出总评建议）
func buildAdvice(a *HardwareAssessment) []HardwareAdvice {
	adv := []HardwareAdvice{}
	// 内存
	memGB := a.Memory.PhysicalGB
	adv = append(adv, HardwareAdvice{
		Area:           "memory",
		Current:        fmt.Sprintf("物理内存 %.1fGB（当前运行模型: %s）", memGB, modelDisplayName()),
		Recommendation: fmt.Sprintf("建议运行模型档位: %s；上下文 %s", a.RecommendedModel, a.ContextWindowHint),
		Reason:         "本地推理常驻内存约为模型量化体积的 1.2-1.5 倍，超配会触发 swap 拖慢整机",
	})
	if memGB < 8 {
		adv = append(adv, HardwareAdvice{
			Area:           "memory",
			Current:        fmt.Sprintf("物理内存仅 %.1fGB", memGB),
			Recommendation: "优先使用云端模型路由（cloudModels 模块），本地仅跑 1.5B-3B 小模型；条件允许升级到 16GB",
			Reason:         "8GB 以下同时跑系统 + llama-server 容易 OOM 被内核杀进程",
		})
	}
	// 磁盘
	if a.Disk.FreeGB < 10 {
		adv = append(adv, HardwareAdvice{
			Area:           "disk",
			Current:        fmt.Sprintf("模型盘可用空间仅 %.1fGB", a.Disk.FreeGB),
			Recommendation: "清理 Models 目录中不用的 GGUF 文件或把 modelDir 迁到大容量磁盘（7B Q4_K_M 约需 4.5GB、14B 约 9GB）",
			Reason:         "模型下载与 kv-cache 落盘都会失败在磁盘写满的临界点",
		})
	} else if a.Disk.FreeGB < 20 {
		adv = append(adv, HardwareAdvice{
			Area:           "disk",
			Current:        fmt.Sprintf("模型盘可用 %.1fGB", a.Disk.FreeGB),
			Recommendation: "下载 14B 级模型前先确认余量（Q4_K_M 约 9GB），建议保留 20GB 以上缓冲",
			Reason:         "避免下载到一半磁盘写满留下损坏文件",
		})
	}
	// GPU
	if !a.GPU.Detected {
		adv = append(adv, HardwareAdvice{
			Area:           "gpu",
			Current:        "未探测到独立 GPU（" + a.GPU.Source + "）",
			Recommendation: "CPU 推理建议：选择 Q4_K_M 及以下量化、并发限制为 1（-c 1）；或优先走云端路由降低本地负载",
			Reason:         "无独显时 CPU 推理吞吐约 3-8 token/s（7B 档），并发会显著劣化响应时间",
		})
	}
	// CPU
	if a.CPU.Cores < 4 {
		adv = append(adv, HardwareAdvice{
			Area:           "cpu",
			Current:        fmt.Sprintf("CPU 仅 %d 核", a.CPU.Cores),
			Recommendation: "本地模型选择 1.5B-3B；网关与本机其他应用争抢 CPU 时优先保障网关（nice/亲和性），或改走云端",
			Reason:         "CPU 核数不足时 llama-server 线程池与系统进程互相抢占，延迟不可控",
		})
	}
	// 总评兜底（保证任何硬件都有可执行建议）
	adv = append(adv, HardwareAdvice{
		Area:           "general",
		Current:        fmt.Sprintf("综合评分 %d/100（%s 档）", a.Scores.Total, a.Grade),
		Recommendation: fmt.Sprintf("当前配置推荐运行: %s", a.RecommendedModel),
		Reason:         "按内存主导 + GPU/CPU 辅助的木桶原则给出，与 stats 面板的实际吞吐交叉验证后微调",
	})
	return adv
}

func modelDisplayName() string {
	running, cur := modelState()
	if !running || cur == "" {
		return "未运行"
	}
	return cur
}

// detectGPU 尽力探测独立 GPU（失败不影响评分，返回探测来源说明）
// v2.1.0 跨平台补全：每个平台提供主探测 + 回退探测，且全部带 5 秒超时
// （system_profiler / powershell 在部分机器上可能长时间无响应，防阻塞评估接口）
func detectGPU() (name, source string) {
	switch runtime.GOOS {
	case "windows":
		// 主探测：wmic（Windows 10 / 早期 Windows 11 可用）
		if out, err := runCmdTimeout(5, "wmic", "path", "win32_VideoController", "get", "name"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				l := strings.TrimSpace(line)
				if l != "" && !strings.EqualFold(l, "name") {
					return l, "wmic win32_VideoController"
				}
			}
		}
		// 回退：PowerShell Get-CimInstance（Windows 11 24H2+ 移除了 wmic）
		if out, err := runCmdTimeout(8, "powershell", "-NoProfile", "-Command",
			"Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				l := strings.TrimSpace(line)
				if l != "" {
					return l, "powershell Get-CimInstance Win32_VideoController"
				}
			}
		}
		return "", "wmic / powershell 均不可用或无显卡记录"
	case "linux":
		// 主探测：lspci（桌面发行版通常自带）
		if out, err := runCmdTimeout(5, "lspci"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(strings.ToLower(line), "vga") || strings.Contains(strings.ToLower(line), "3d controller") {
					seg := strings.SplitN(line, ":", 3)
					if len(seg) == 3 {
						return strings.TrimSpace(seg[2]), "lspci"
					}
				}
			}
		}
		// 回退：nvidia-smi（无 lspci 的最小化服务器 / 容器环境）
		if out, err := runCmdTimeout(5, "nvidia-smi", "--query-gpu=name", "--format=csv,noheader"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				l := strings.TrimSpace(line)
				if l != "" {
					return l, "nvidia-smi"
				}
			}
		}
		return "", "lspci / nvidia-smi 均不可用或无独立显卡"
	case "darwin":
		// macOS：system_profiler（Intel 核显与 Apple Silicon 均能识别）
		if out, err := runCmdTimeout(8, "system_profiler", "SPDisplaysDataType"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "Chipset Model") {
					seg := strings.SplitN(line, ":", 2)
					if len(seg) == 2 {
						n := strings.TrimSpace(seg[1])
						if n != "" {
							return n, "system_profiler SPDisplaysDataType"
						}
					}
				}
			}
		}
		return "", "system_profiler 不可用或未返回 Chipset Model"
	}
	return "", "平台不支持 GPU 探测"
}

// runCmdTimeout 带超时的命令探测（GPU 检测专用：外部工具可能挂起，绝不阻塞评估接口）
func runCmdTimeout(sec int, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(sec)*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// handleHardwareAssessment GET /api/admin/hardware/assessment（hardwareAdvisor 模块）
func handleHardwareAssessment(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, assessHardware())
}

func nowStamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

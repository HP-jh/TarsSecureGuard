package main

import (
	"fmt"
	"net/http"
	"runtime"
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
		Model string `json:"model"` // v3.0.1 Tier 1 静态属性（探测失败留空）
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
	Board struct {
		Model string `json:"model"` // v3.0.1 Tier 1 静态属性（机型/主板，权限不足留空）
	} `json:"board"`
	Tier1 struct {
		Active        bool   `json:"active"`        // 本次快照是否为 Tier 1 数据
		Cached        bool   `json:"cached"`        // 是否命中缓存（命中则未 spawn 子进程）
		Degraded      bool   `json:"degraded"`      // 是否降级 Tier 0
		DegradeReason string `json:"degradeReason"` // 降级原因（关闭/熔断/权限不足/篡改/平台不支持）
		Source        string `json:"source"`        // 探测来源说明
	} `json:"tier1"`
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
	// v3.0.1：静态属性（CPU 型号 / GPU 型号 / 机型）唯一来源为 Tier 1 快照
	// （tier1.go，锦衣卫红线 TSG-TIER1-2026-0929）。旧 v2.1.0 的 wmic /
	// powershell -Command / 裸 lspci / nvidia-smi / system_profiler 直调已全部移除——
	// 一切系统原生命令调用必须过 tier1Run 白名单通道。
	// 动态指标（磁盘 / 可用内存 / 核数）永远走 Tier 0，不进缓存。
	snap := tier1HardwareSnapshot()
	a.CPU.Model = snap.CPUModel
	a.Board.Model = snap.BoardModel
	a.Tier1.Active = snap.Active
	a.Tier1.Cached = snap.Cached
	a.Tier1.Degraded = snap.Degraded
	a.Tier1.DegradeReason = snap.DegradeReason
	a.Tier1.Source = snap.Source
	a.GPU.Name = snap.GPUModel
	a.GPU.Source = snap.Source
	if snap.Degraded {
		a.GPU.Source = "tier0 降级（" + snap.DegradeReason + "）"
	} else if !snap.Active {
		a.GPU.Source = "tier0（Tier 1 关闭）"
	}
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

// v3.0.1 起本文件不再直接执行任何系统原生命令：
//   - 旧 detectGPU（wmic / powershell -Command / 裸 lspci / nvidia-smi /
//     system_profiler 直调）违反锦衣卫红线 [TIER1_EXEC_MANDATORY]/[TIER1_ALLOWLIST]，
//     已整体移除；GPU/CPU 型号/机型静态属性统一由 tier1HardwareSnapshot 提供
//     （白名单 + 超时 + 进程树清理 + 审计 + 缓存，详见 tier1.go）。
//   - runCmdTimeout（GPU 检测专用的裸超时执行器）随之删除，避免留下绕开
//     白名单的第二条执行通道。
//
// handleHardwareAssessment GET /api/admin/hardware/assessment（hardwareAdvisor 模块）
func handleHardwareAssessment(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, assessHardware())
}

func nowStamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

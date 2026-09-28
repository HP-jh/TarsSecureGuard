package main

import (
	"fmt"
	"math"
	"runtime"
	"strings"
)

// ===================== 硬件评估（v2.0.0 新增，模块 hardwareAdvisor）=====================
//
// 评估 CPU / 内存 / 磁盘 / GPU 四个维度，输出 0-100 分与档位（A/B/C/D），
// 并给出是否适合跑本地大模型的结论与推荐参数。

type HardwareAssessment struct {
	Grade   string             `json:"grade"`   // A 优秀 | B 良好 | C 一般 | D 较弱
	Scores  HardwareScores     `json:"scores"`  // 各维度得分
	Advice  string             `json:"advice"`  // 总体建议
	Details map[string]string  `json:"details"` // 探测明细
	Model   ModelRecommendation `json:"modelRecommendation"`
}

type HardwareScores struct {
	CPU    int `json:"cpu"`
	Memory int `json:"memory"`
	Disk   int `json:"disk"`
	GPU    int `json:"gpu"`
	Total  int `json:"total"`
}

type ModelRecommendation struct {
	CanRunLocal  bool   `json:"canRunLocal"`
	MaxModelSize string `json:"maxModelSize"` // 推荐最大参数量级
	Quantization string `json:"quantization"` // 推荐量化格式
	ContextSize  int    `json:"contextSize"`  // 推荐上下文长度
	Reason       string `json:"reason"`
}

// assessHardware 执行硬件评估（纯本地探测，不联网）
func assessHardware() HardwareAssessment {
	details := map[string]string{}

	// ---- CPU ----
	cores := runtime.NumCPU()
	cpuScore := scoreCPU(cores)
	details["cpuCores"] = fmt.Sprintf("%d 逻辑核心", cores)

	// ---- 内存 ----
	memGB := physicalMemoryGB()
	memScore := scoreMemory(memGB)
	details["memoryGB"] = fmt.Sprintf("%.1f GB 物理内存", memGB)

	// ---- 磁盘 ----
	diskTotal, diskFree := probeDisk()
	diskScore := scoreDisk(diskTotal, diskFree)
	details["diskTotalGB"] = fmt.Sprintf("%.0f GB", diskTotal)
	details["diskFreeGB"] = fmt.Sprintf("%.0f GB 可用", diskFree)

	// ---- GPU ----
	gpuName, gpuVram := probeGPU()
	gpuScore := scoreGPU(gpuVram)
	if gpuName != "" {
		details["gpu"] = gpuName
		details["gpuVramGB"] = fmt.Sprintf("%.1f GB", gpuVram)
	} else {
		details["gpu"] = "未检测到独立 GPU（或当前平台不支持探测）"
	}

	total := (cpuScore + memScore + diskScore + gpuScore) / 4
	grade := gradeFromScore(total)
	rec := recommendModel(memGB, gpuVram, grade)
	advice := buildAdvice(grade, rec)

	return HardwareAssessment{
		Grade:   grade,
		Scores:  HardwareScores{CPU: cpuScore, Memory: memScore, Disk: diskScore, GPU: gpuScore, Total: total},
		Advice:  advice,
		Details: details,
		Model:   rec,
	}
}

func scoreCPU(cores int) int {
	switch {
	case cores >= 16:
		return 95
	case cores >= 12:
		return 85
	case cores >= 8:
		return 70
	case cores >= 4:
		return 50
	default:
		return 30
	}
}

func scoreMemory(gb float64) int {
	switch {
	case gb >= 32:
		return 95
	case gb >= 16:
		return 80
	case gb >= 8:
		return 60
	case gb >= 4:
		return 40
	default:
		return 20
	}
}

func scoreDisk(totalGB, freeGB float64) int {
	// 可用空间是关键：至少要放得下模型文件
	switch {
	case freeGB >= 100:
		return 90
	case freeGB >= 50:
		return 75
	case freeGB >= 20:
		return 55
	case freeGB >= 10:
		return 35
	default:
		return 15
	}
}

func scoreGPU(vramGB float64) int {
	switch {
	case vramGB >= 16:
		return 95
	case vramGB >= 12:
		return 85
	case vramGB >= 8:
		return 70
	case vramGB >= 4:
		return 50
	case vramGB >= 2:
		return 35
	default:
		return 20 // 无独显也能 CPU 跑，只是慢
	}
}

func gradeFromScore(s int) string {
	switch {
	case s >= 85:
		return "A"
	case s >= 70:
		return "B"
	case s >= 50:
		return "C"
	default:
		return "D"
	}
}

// recommendModel 根据内存/显存推荐可跑的模型量级
func recommendModel(memGB, vramGB float64, grade string) ModelRecommendation {
	// 可用预算：优先显存，否则取内存的 60%（留系统与其他程序）
	budget := vramGB
	if budget < 2 {
		budget = memGB * 0.6
	}
	rec := ModelRecommendation{Quantization: "Q4_K_M", ContextSize: 2048}
	// Q4 量化下每 1B 参数约 0.6-0.7GB；粗略映射
	switch {
	case budget >= 10:
		rec.CanRunLocal = true
		rec.MaxModelSize = "14B"
		rec.Quantization = "Q4_K_M"
		rec.ContextSize = 4096
		rec.Reason = "资源充足，可流畅运行 14B 级 Q4 量化模型"
	case budget >= 6:
		rec.CanRunLocal = true
		rec.MaxModelSize = "7B-8B"
		rec.Quantization = "Q4_K_M"
		rec.ContextSize = 4096
		rec.Reason = "可运行 7B/8B 级 Q4 量化模型，响应速度可接受"
	case budget >= 3.5:
		rec.CanRunLocal = true
		rec.MaxModelSize = "3B"
		rec.Quantization = "Q4_K_M"
		rec.ContextSize = 2048
		rec.Reason = "可运行 3B 级 Q4 量化小模型，建议短上下文"
	case budget >= 2:
		rec.CanRunLocal = true
		rec.MaxModelSize = "1.5B"
		rec.Quantization = "Q4_0"
		rec.ContextSize = 1024
		rec.Reason = "仅推荐 0.5B-1.5B 级小模型，速度较慢"
	default:
		rec.CanRunLocal = false
		rec.MaxModelSize = "不建议本地推理"
		rec.Quantization = "-"
		rec.ContextSize = 0
		rec.Reason = "资源不足，建议使用云端模型或升级硬件"
	}
	return rec
}

func buildAdvice(grade string, rec ModelRecommendation) string {
	var b strings.Builder
	switch grade {
	case "A":
		b.WriteString("硬件优秀，本地大模型体验良好。")
	case "B":
		b.WriteString("硬件良好，可胜任多数本地模型场景。")
	case "C":
		b.WriteString("硬件一般，建议使用 3B 以内小模型或云端模型。")
	case "D":
		b.WriteString("硬件较弱，本地推理体验有限，默认以云端模型为主。")
	}
	b.WriteString(rec.Reason)
	b.WriteString("。")
	return b.String()
}

// probeDisk 探测磁盘总量与可用空间（GB）
func probeDisk() (float64, float64) {
	if du, err := getDiskUsage(exeDrive()); err == nil {
		gb := func(b uint64) float64 { return float64(b) / 1024 / 1024 / 1024 }
		return gb(du.Total), gb(du.Free)
	}
	return 0, 0
}

// ===================== 硬件评估 HTTP =====================
func handleHardwareAssessment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	a := assessHardware()
	n, _, _ := userFromRequest(r)
	auditLog("HARDWARE_ASSESS", n, fmt.Sprintf("档位 %s 总分 %d 推荐 %s", a.Grade, a.Scores.Total, a.Model.MaxModelSize))
	writeJSON(w, a)
}

// 避免未使用导入（math 在更细粒度评分时使用）
var _ = math.Round

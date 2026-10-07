package main

import (
	"fmt"
	"runtime"
	"strings"
)

// ===================== 设备信息 =====================
func getDeviceInfo() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var diskTotal, diskFree uint64
	if du, err := getDiskUsage(exeDrive()); err == nil {
		diskTotal = du.Total
		diskFree = du.Free
	}

	running, cur := modelState()
	return map[string]interface{}{
		"cpu":               fmt.Sprintf("%d cores", runtime.NumCPU()),
		"memory":            fmt.Sprintf("%.1fGB sys alloc", float64(m.Sys)/1024/1024/1024),
		"os":                runtime.GOOS + " " + runtime.GOARCH,
		"localModelRunning": running,
		"currentModel":      cur,
		"localModels":       getLocalModelList(),
		"modelDirExists":    fileExists(modelDir),
		"llamaDirExists":    fileExists(llamaDir),
		"goVersion":         runtime.Version(),
		"lmstudio":          lmsReachable(),
		"ollama":            ollamaReachable(),
		"diskTotal":         diskTotal,
		"diskFree":          diskFree,
	}
}

type diskUsage struct {
	Total uint64
	Free  uint64
}

// ===================== 本地服务发现 =====================
func discoverLocal() map[string]interface{} {
	running, cur := modelState()
	services := []map[string]interface{}{
		{"name": "llama-local", "type": "local-gguf", "address": fmt.Sprintf("127.0.0.1:%d", modelPort), "status": boolStatus(running), "detail": cur},
		{"name": "lm-studio", "type": "openai-compatible", "address": "127.0.0.1:1234", "status": boolStatus(lmsReachable()), "detail": ""},
		{"name": "ollama", "type": "ollama", "address": "127.0.0.1:11434", "status": boolStatus(ollamaReachable()), "detail": ""},
	}
	for _, s := range cfg.MCP.ExternalServers {
		exe := s.Command
		services = append(services, map[string]interface{}{
			"name":    "mcp-" + s.Name,
			"type":    "mcp-stdio",
			"address": s.Command + " " + strings.Join(s.Args, " "),
			"status":  boolStatus(fileExists(exe)),
			"detail":  s.Name,
		})
	}
	return map[string]interface{}{"services": services}
}

func boolStatus(b bool) string {
	if b {
		return "online"
	}
	return "offline"
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type ModelInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Status  string `json:"status"`
	Source  string `json:"source"`
	Size    string `json:"size,omitempty"`
	Backend string `json:"backend"`
}

type GGUFModel struct {
	ID   string
	File string
}

var ggufModels = []GGUFModel{
	{ID: "qwen2.5-3b", File: "qwen2.5-3b-instruct-q4_k_m.gguf"},
	{ID: "qwen2.5-7b", File: "qwen2.5-7b-instruct-q3_k_m.gguf"},
	{ID: "qwen2.5-coder-3b", File: "qwen2.5-coder-3b-instruct-q4_k_m.gguf"},
}

func getLocalModelList() []map[string]interface{} {
	var list []map[string]interface{}
	running, cur := modelState()
	for _, gm := range ggufModels {
		p := filepath.Join(modelDir, gm.File)
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		sizeGB := float64(info.Size()) / 1024 / 1024 / 1024
		status := "offline"
		if running && cur == gm.ID {
			status = "online"
		}
		list = append(list, map[string]interface{}{
			"name":   gm.ID,
			"file":   gm.File,
			"size":   fmt.Sprintf("%.2fGB", sizeGB),
			"status": status,
			"source": "local",
		})
	}
	return list
}

func getModels() []ModelInfo {
	var ms []ModelInfo
	for _, gm := range ggufModels {
		p := filepath.Join(modelDir, gm.File)
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		sizeStr := fmt.Sprintf("%.2fGB", float64(info.Size())/1024/1024/1024)
		status := "offline"
		if modelRunning && currentModel == gm.ID {
			status = "online"
		}
		ms = append(ms, ModelInfo{ID: gm.ID, Name: gm.ID, Type: "chat", Status: status, Source: "local", Size: sizeStr, Backend: "llama"})
	}
	if lmsReachable() {
		for _, m := range detectLMStudio() {
			ms = append(ms, m)
		}
	}
	if ollamaReachable() {
		for _, m := range detectOllama() {
			ms = append(ms, m)
		}
	}
	for _, cc := range allCloudCfgs() {
		for _, mdl := range cc.Models {
			ms = append(ms, ModelInfo{ID: mdl, Name: mdl, Type: "chat", Status: "configured", Source: "cloud", Backend: cc.Name})
		}
	}
	return ms
}

func allCloudCfgs() []CloudCfg {
	var out []CloudCfg
	if cfg.Cloud.OpenAI.BaseURL != "" && cfg.Cloud.OpenAI.APIKey != "" {
		out = append(out, cfg.Cloud.OpenAI)
	}
	if cfg.Cloud.DeepSeek.BaseURL != "" && cfg.Cloud.DeepSeek.APIKey != "" {
		out = append(out, cfg.Cloud.DeepSeek)
	}
	for _, c := range cfg.Cloud.Custom {
		if c.BaseURL != "" && c.APIKey != "" {
			out = append(out, c)
		}
	}
	return out
}

func findGGUFFile(id string) string {
	for _, gm := range ggufModels {
		if gm.ID == id {
			return filepath.Join(modelDir, gm.File)
		}
	}
	for _, gm := range ggufModels {
		if gm.File == id {
			return filepath.Join(modelDir, gm.File)
		}
	}
	return ""
}

func startLocalModel(id string) error {
	mu.Lock()
	if modelRunning {
		mu.Unlock()
		return nil
	}
	if starting {
		mu.Unlock()
		return fmt.Errorf("模型正在启动中，请稍候")
	}
	starting = true
	mu.Unlock()

	modelPath := findGGUFFile(id)
	if modelPath == "" {
		mu.Lock()
		starting = false
		mu.Unlock()
		return fmt.Errorf("模型不存在: %s（可用: qwen2.5-3b / qwen2.5-7b / qwen2.5-coder-3b）", id)
	}
	serverPath := filepath.Join(llamaDir, "llama-server.exe")
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		mu.Lock()
		starting = false
		mu.Unlock()
		return fmt.Errorf("模型文件缺失: %s", modelPath)
	}
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		mu.Lock()
		starting = false
		mu.Unlock()
		return fmt.Errorf("推理引擎缺失: %s", serverPath)
	}

	cmd := exec.Command(serverPath, "-m", modelPath, "--port", strconv.Itoa(modelPort), "-ngl", "0", "-c", "4096")
	cmd.Dir = llamaDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := cmd.Start(); err != nil {
		mu.Lock()
		starting = false
		mu.Unlock()
		return fmt.Errorf("启动失败: %v", err)
	}
	mu.Lock()
	modelProcess = cmd.Process
	modelRunning = true
	currentModel = id
	starting = false
	mu.Unlock()
	logMsg(fmt.Sprintf("[MODEL] 本地模型 %s 启动 (PID %d, port %d)", id, cmd.Process.Pid, modelPort))

	go func() {
		for i := 0; i < 60; i++ {
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/v1/models", modelPort))
			if err == nil {
				resp.Body.Close()
				logMsg(fmt.Sprintf("[MODEL] %s 就绪", id))
				return
			}
			time.Sleep(1 * time.Second)
		}
	}()

	go func() {
		cmd.Wait()
		mu.Lock()
		modelRunning = false
		modelProcess = nil
		currentModel = ""
		mu.Unlock()
		logMsg("[MODEL] 本地模型已停止")
	}()
	return nil
}

func stopLocalModel() {
	mu.Lock()
	if modelProcess != nil {
		modelProcess.Kill()
		modelProcess = nil
	}
	modelRunning = false
	currentModel = ""
	mu.Unlock()
	logMsg("[MODEL] 本地模型已停止")
}

func lmsReachable() bool {
	resp, err := http.Get(lmStudioBase + "/v1/models")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func ollamaReachable() bool {
	resp, err := http.Get(ollamaBase + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func detectLMStudio() []ModelInfo {
	var ms []ModelInfo
	if !lmsReachable() {
		return ms
	}
	resp, err := http.Get(lmStudioBase + "/v1/models")
	if err != nil {
		return ms
	}
	defer resp.Body.Close()
	var data struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&data)
	for _, m := range data.Data {
		id := m.ID
		ms = append(ms, ModelInfo{ID: "lmstudio/" + id, Name: id, Type: "chat", Status: "online", Source: "lmstudio", Backend: "lmstudio"})
	}
	return ms
}

func detectOllama() []ModelInfo {
	var ms []ModelInfo
	if !ollamaReachable() {
		return ms
	}
	resp, err := http.Get(ollamaBase + "/api/tags")
	if err != nil {
		return ms
	}
	defer resp.Body.Close()
	var data struct {
		Models []struct {
			Name       string `json:"name"`
			Size       int64  `json:"size"`
			ModifiedAt string `json:"modified_at"`
		} `json:"models"`
	}
	json.NewDecoder(resp.Body).Decode(&data)
	for _, m := range data.Models {
		sizeStr := fmt.Sprintf("%.2fGB", float64(m.Size)/1024/1024/1024)
		ms = append(ms, ModelInfo{ID: "ollama/" + m.Name, Name: m.Name, Type: "chat", Status: "online", Source: "ollama", Size: sizeStr, Backend: "ollama"})
	}
	return ms
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	ms := getModels()
	writeJSON(w, map[string]interface{}{"models": ms, "total": len(ms)})
}

func handleModelStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}
	id := body["model"]
	if id == "" {
		id = "qwen2.5-3b"
	}
	if err := startLocalModel(id); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"success": true, "running": true, "model": id})
}

func handleModelStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	stopLocalModel()
	writeJSON(w, map[string]interface{}{"success": true, "running": false})
}

func handleOpenModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", modelDir)
	case "darwin":
		cmd = exec.Command("open", modelDir)
	default:
		cmd = exec.Command("xdg-open", modelDir)
	}
	if err := cmd.Start(); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	logMsg("[MODEL] 已打开模型目录: " + modelDir)
	writeJSON(w, map[string]interface{}{"success": true, "path": modelDir})
}

func handleModelStatus(w http.ResponseWriter, r *http.Request) {
	running, cur := modelState()
	writeJSON(w, map[string]interface{}{"running": running, "model": cur})
}

func handleDevice(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getDeviceInfo())
}

func handleDeviceScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	recommendations := []map[string]interface{}{
		{"name": "qwen2.5-3b-instruct", "size": "1.9GB", "url": "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/qwen2.5-3b-instruct-q4_k_m.gguf"},
		{"name": "qwen2.5-coder-3b", "size": "1.9GB", "url": "https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct-GGUF/resolve/main/qwen2.5-coder-3b-instruct-q4_k_m.gguf"},
	}
	writeJSON(w, map[string]interface{}{
		"cpu":             fmt.Sprintf("%d cores", runtime.NumCPU()),
		"memory":          "Auto-detect",
		"gpu":             "Auto-detect",
		"disk":            exeDrive() + " drive",
		"lmstudio":        lmsReachable(),
		"ollama":          ollamaReachable(),
		"recommendations": recommendations,
	})
}

func handleModelDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}
	name := body["name"]
	urlStr := body["url"]
	logMsg("[DOWNLOAD] 开始下载模型: " + name)
	go func() {
		if err := downloadModel(name, urlStr); err != nil {
			logMsg("[DOWNLOAD] " + name + " 失败: " + err.Error())
		} else {
			logMsg("[DOWNLOAD] " + name + " 完成")
		}
	}()
	writeJSON(w, map[string]interface{}{"success": true, "message": "Download started: " + name})
}

type dlStatus struct {
	Name  string `json:"name"`
	Done  bool   `json:"done"`
	Error string `json:"error,omitempty"`
	Bytes int64  `json:"bytes"`
	Total int64  `json:"total"`
	Pct   int    `json:"pct"`
}

var (
	dlMu    sync.Mutex
	dlState = map[string]*dlStatus{}
)

func downloadModel(name, urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("no url")
	}
	if !isHTTPURL(urlStr) {
		return fmt.Errorf("仅支持 http/https 下载链接")
	}
	dlMu.Lock()
	st := &dlStatus{Name: name}
	dlState[name] = st
	dlMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		dlMu.Lock()
		st.Error = err.Error()
		st.Done = true
		dlMu.Unlock()
		return err
	}
	resp, err := downloadClient.Do(req)
	if err != nil {
		dlMu.Lock()
		st.Error = err.Error()
		st.Done = true
		dlMu.Unlock()
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e := fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
		dlMu.Lock()
		st.Error = e.Error()
		st.Done = true
		dlMu.Unlock()
		return e
	}
	base := filepath.Base(urlStr)
	if base == "" || base == "." || base == "/" {
		e := fmt.Errorf("无法从 URL 推断文件名")
		dlMu.Lock()
		st.Error = e.Error()
		st.Done = true
		dlMu.Unlock()
		return e
	}
	dlMu.Lock()
	st.Total = resp.ContentLength
	dlMu.Unlock()
	dest := filepath.Join(modelDir, base)
	out, err := os.Create(dest)
	if err != nil {
		dlMu.Lock()
		st.Error = err.Error()
		st.Done = true
		dlMu.Unlock()
		return err
	}
	defer out.Close()
	buf := make([]byte, 256<<10)
	var written int64
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				dlMu.Lock()
				st.Error = werr.Error()
				st.Done = true
				dlMu.Unlock()
				return werr
			}
			written += int64(n)
			if written > maxModelDownloadBytes {
				e := fmt.Errorf("模型文件超过 %d 字节，已中止", maxModelDownloadBytes)
				dlMu.Lock()
				st.Error = e.Error()
				st.Done = true
				dlMu.Unlock()
				return e
			}
			dlMu.Lock()
			st.Bytes = written
			if st.Total > 0 {
				st.Pct = int(written * 100 / st.Total)
			}
			dlMu.Unlock()
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			dlMu.Lock()
			st.Error = rerr.Error()
			st.Done = true
			dlMu.Unlock()
			return rerr
		}
	}
	dlMu.Lock()
	st.Bytes = written
	st.Pct = 100
	st.Done = true
	dlMu.Unlock()
	return nil
}

func handleModelDownloadStatus(w http.ResponseWriter, r *http.Request) {
	dlMu.Lock()
	out := make([]*dlStatus, 0, len(dlState))
	for _, st := range dlState {
		cp := *st
		out = append(out, &cp)
	}
	dlMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, map[string]interface{}{"downloads": out})
}

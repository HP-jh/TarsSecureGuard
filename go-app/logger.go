package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	logDir    string
	logFileMu sync.Mutex
)

const (
	maxLogFileBytes = 5 << 20
)

func initLogDir() {
	logDir = filepath.Join(appDir(), "logs")
	os.MkdirAll(logDir, 0755)
}

func appendLog(filename, line string) {
	logFileMu.Lock()
	defer logFileMu.Unlock()

	path := filepath.Join(logDir, filename)

	if info, err := os.Stat(path); err == nil && info.Size() > maxLogFileBytes {
		os.WriteFile(path, []byte{}, 0644)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), line)
}

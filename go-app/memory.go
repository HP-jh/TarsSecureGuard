package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func memoryPath() string {
	return filepath.Join(filepath.Dir(configPath), "memory.json")
}

func saveMemory() {
	memoryMu.Lock()
	data, _ := json.MarshalIndent(memory, "", "  ")
	memoryMu.Unlock()
	os.WriteFile(memoryPath(), data, 0644)
}

func loadMemory() {
	data, err := os.ReadFile(memoryPath())
	if err != nil {
		return
	}
	json.Unmarshal(data, &memory)
}

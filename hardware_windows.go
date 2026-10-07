//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// physicalMemoryGB Windows：GlobalMemoryStatusEx 取物理内存总量
type memoryStatusEx struct {
	dwLength     uint32
	dwMemoryLoad uint32
	ullTotalPhys uint64
	ullAvailPhys uint64
	ullTotalPage uint64
	ullAvailPage uint64
	ullTotalVirt uint64
	ullAvailVirt uint64
	ullAvailExt  uint64
}

func physicalMemoryGB() float64 {
	var m memoryStatusEx
	m.dwLength = uint32(unsafe.Sizeof(m))
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	r1, _, _ := proc.Call(uintptr(unsafe.Pointer(&m)))
	if r1 == 0 {
		return 0
	}
	return float64(m.ullTotalPhys) / 1024 / 1024 / 1024
}

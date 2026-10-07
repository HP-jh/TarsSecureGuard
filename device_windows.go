//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// getDiskUsage Windows 实现：调用 kernel32.dll GetDiskFreeSpaceExW
func getDiskUsage(path string) (diskUsage, error) {
	var du diskUsage
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return du, err
	}
	dll := syscall.NewLazyDLL("kernel32.dll")
	proc := dll.NewProc("GetDiskFreeSpaceExW")
	r, _, cerr := proc.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&du.Free)),
		uintptr(unsafe.Pointer(&du.Total)),
		0,
	)
	if r == 0 {
		if cerr != nil {
			return du, cerr
		}
		return du, fmt.Errorf("GetDiskFreeSpaceEx failed")
	}
	return du, nil
}

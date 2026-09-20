//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// ===================== Windows DPAPI 密钥加密 =====================
//
// 使用 Windows DPAPI (CryptProtectData) 将 API Key 加密后落盘。
// 加密后的数据只能在同一 Windows 用户账户下解密，即使别人拿到 config.json
// 也无法直接读取密钥。非 Windows 平台走 dpapi_other.go 降级。

var (
	dllCrypt32              = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectData    = dllCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData  = dllCrypt32.NewProc("CryptUnprotectData")
	dllKernel32             = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree           = dllKernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

// dpapiEncrypt 用当前用户上下文加密数据
func dpapiEncrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	in := dataBlob{cbData: uint32(len(plaintext)), pbData: &plaintext[0]}
	var out dataBlob
	r, _, callErr := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, callErr
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	result := make([]byte, out.cbData)
	copy(result, unsafe.Slice(out.pbData, out.cbData))
	return result, nil
}

// dpapiDecrypt 用当前用户上下文解密数据
func dpapiDecrypt(encrypted []byte) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, nil
	}
	in := dataBlob{cbData: uint32(len(encrypted)), pbData: &encrypted[0]}
	var out dataBlob
	r, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, callErr
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	result := make([]byte, out.cbData)
	copy(result, unsafe.Slice(out.pbData, out.cbData))
	return result, nil
}

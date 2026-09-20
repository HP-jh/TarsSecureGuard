//go:build !windows

package main

// dpapiEncrypt 在非 Windows 平台降级：直接返回原文（不加密）
func dpapiEncrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

// dpapiDecrypt 在非 Windows 平台降级：直接返回原文
func dpapiDecrypt(encrypted []byte) ([]byte, error) {
	return encrypted, nil
}

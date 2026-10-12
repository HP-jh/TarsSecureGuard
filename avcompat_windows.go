//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// 常见安全软件进程名（不带 .exe）
var knownAVProcesses = []string{
	"360Safe", "360Tray", "QHSafeTray", "QHActiveDefense", // 360
	"HipsTray", "HR", "HipsMain",                          // 火绒
	"MsMpEng", "MpCmdRun", "SecurityHealthService",        // Windows Defender
	"avast", "avgsvc", "mcshield", "ccsvchst",             // 其他国际杀软
}

func scanAVCompatPlatform(status *AVCompatStatus) {
	// 1) 检测安全软件进程（通过 tasklist）
	for _, proc := range knownAVProcesses {
		if isProcessRunning(proc) {
			status.DetectedAVs = append(status.DetectedAVs, proc)
		}
	}

	// 2) 尝试添加到 Windows Defender 排除列表（需管理员权限）
	if isAdminRuntime {
		status.DefenderExcluded = tryAddDefenderExclusion(status.SelfPath)
		if !status.DefenderExcluded {
			status.Recommendations = append(status.Recommendations,
				"已尝试添加 Windows Defender 排除项但失败，建议手动在「病毒和威胁防护 > 排除项」中添加本程序路径")
		}
	} else {
		status.Recommendations = append(status.Recommendations,
			"当前未以管理员身份运行，无法自动添加 Windows Defender 排除项。建议以管理员身份运行一次本程序，或手动添加排除项")
	}

	// 3) 写入注册表「受信任发布者」标识（让部分安全软件降低误报概率）
	status.TrustedRegistered = tryRegisterTrusted()
	if !status.TrustedRegistered {
		status.Recommendations = append(status.Recommendations,
			"注册表信任标识写入失败，通常不影响运行")
	}

	// 4) 针对 360 的特殊建议
	if hasString(status.DetectedAVs, "360") {
		status.Recommendations = append(status.Recommendations,
			"检测到 360 安全软件。如被误报，请在 360 中添加「信任区」或「白名单」，路径: "+status.SelfPath)
	}
	// 5) 针对火绒的特殊建议
	if hasString(status.DetectedAVs, "Hips") || hasString(status.DetectedAVs, "HR") {
		status.Recommendations = append(status.Recommendations,
			"检测到火绒安全软件。如被误报，请在火绒「信任区」或「病毒隔离区」中恢复并添加信任")
	}
}

func isProcessRunning(name string) bool {
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s.exe", name), "/FO", "CSV", "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), name)
}

func tryAddDefenderExclusion(path string) bool {
	// 使用 PowerShell 添加 Windows Defender 排除项
	ps := fmt.Sprintf(
		"Add-MpPreference -ExclusionPath '%s'; Add-MpPreference -ExclusionPath '%s'",
		path, filepath.Dir(path),
	)
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		avCompatLog(fmt.Sprintf("Defender 排除项添加失败: %v", err))
		return false
	}
	avCompatLog("已添加 Windows Defender 排除项: " + path)
	return true
}

func tryRegisterTrusted() bool {
	// 在 HKCU 下写入一个标识键（不需要管理员）
	// 虽然这不能真正让系统信任未签名二进制，但某些安全软件会读取此键作为辅助判断
	cmd := exec.Command("reg", "add",
		`HKCU\Software\TarsSecureGuard`, "/v", "InstallPath", "/d", appDir(), "/f")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func hasString(arr []string, substr string) bool {
	for _, s := range arr {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

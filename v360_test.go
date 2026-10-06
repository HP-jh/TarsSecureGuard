package main

// v3.6.0 统一安装包 + 官方引流站：
// 1) install.sh / install.ps1 自动识别 OS 与架构（静态断言关键检测逻辑存在）
// 2) site/ 官网 SEO 基线（meta description / JSON-LD / canonical / GitHub 入口）

import (
	"os"
	"strings"
	"testing"
)

func TestV360VersionBumped(t *testing.T) {
	// v3.6.0 已发布收口；此处只做下限校验（当前版本锁由最新版测试维护）
	if version < "3.6.0" {
		t.Fatalf("version = %q, want >= 3.6.0", version)
	}
}

func TestV360InstallerSh(t *testing.T) {
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("install.sh 缺失: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		"uname -s",          // OS 识别
		"uname -m",          // 架构识别
		"x86_64|amd64",      // amd64 映射
		"aarch64|arm64",     // arm64 映射
		"HP-jh/TarsSecureGuard", // GitHub Release 源
		"TSG_BASE_URL",      // 镜像/本地目录覆盖（可测性）
		"TSG_INSTALL_DIR",   // 安装目录可覆盖
		"install.ps1",       // Windows 引导
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh 缺少关键逻辑标记 %q", want)
		}
	}
}

func TestV360InstallerPs1(t *testing.T) {
	b, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("install.ps1 缺失: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		"PROCESSOR_ARCHITECTURE", // 架构识别
		"tsg-windows-",           // 资产命名
		"HP-jh/TarsSecureGuard",  // GitHub Release 源
		"SetEnvironmentVariable", // PATH 写入
		"latest/download",        // latest 版本解析
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.ps1 缺少关键逻辑标记 %q", want)
		}
	}
}

func TestV360SiteSEO(t *testing.T) {
	b, err := os.ReadFile("site/index.html")
	if err != nil {
		t.Fatalf("site/index.html 缺失: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`name="description"`,                     // SEO 描述
		`rel="canonical"`,                        // canonical
		`application/ld+json`,                    // 结构化数据
		"SoftwareApplication",                    // JSON-LD 类型
		"https://github.com/HP-jh/TarsSecureGuard", // GitHub 入口
		"install.sh",                             // 一键安装命令
		"install.ps1",
		`property="og:title"`,                    // Open Graph
	} {
		if !strings.Contains(s, want) {
			t.Errorf("site/index.html 缺少 SEO 标记 %q", want)
		}
	}
	for _, f := range []string{"site/robots.txt", "site/sitemap.xml"} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s 缺失: %v", f, err)
		}
	}
	rb, _ := os.ReadFile("site/robots.txt")
	if !strings.Contains(string(rb), "Sitemap:") {
		t.Errorf("robots.txt 未声明 Sitemap")
	}
	sb, _ := os.ReadFile("site/sitemap.xml")
	if !strings.Contains(string(sb), "hp-jh.github.io") {
		t.Errorf("sitemap.xml 未包含站点 URL")
	}
}

// v4.33.0 SQL注入语义分析层测试
package main

import (
	"testing"
)

func TestV4330VersionBumped(t *testing.T) {
	if version != "4.33.0" {
		t.Fatalf("version expected 4.33.0, got %s", version)
	}
}

// TestV4330SQLSemanticExists SQL语义分析模块必须存在
func TestV4330SQLSemanticExists(t *testing.T) {
	// 语义匹配函数必须非空
	if sqlSemanticMatch("SELECT * FROM users") == "" {
		// 正常SQL不应命中，函数应存在且工作
	}
	// 注入应命中
	if sqlSemanticMatch("UNI/**/ON SEL/**/ECT 1") == "" {
		t.Error("SQL语义分析未检测到注释绕过注入")
	}
	if sqlSemanticMatch("CONCAT('UN','ION')") == "" {
		t.Error("SQL语义分析未检测到拼接注入")
	}
	if sqlSemanticMatch("1 AND SLEEP(5)") == "" {
		t.Error("SQL语义分析未检测到时间盲注")
	}
}

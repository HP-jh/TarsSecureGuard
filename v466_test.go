// v4.6.6 小白化测试：密钥引导弹窗 + 人话错误提示 + 告别原生 alert/prompt
package main

import (
	"strings"
	"testing"
)

// TestV466VersionBumped 版本号必须已升至 4.16.0
func TestV466VersionBumped(t *testing.T) {
	if version != "4.18.0" {
		t.Fatalf("version expected 4.16.0, got %s", version)
	}
}

func v466Frontend(t *testing.T) string {
	html, err := frontendFS.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatalf("读取前端资源失败: %v", err)
	}
	return string(html)
}

// TestV466NoNativeAlertPrompt 前端不得再使用浏览器原生 alert()/prompt()——
// 原生弹窗文案没法换行排版、样式突兀、对小白不友好，一律改为应用内 toast / 引导弹窗
func TestV466NoNativeAlertPrompt(t *testing.T) {
	s := v466Frontend(t)
	if strings.Contains(s, "alert(") {
		t.Error("前端仍存在原生 alert() 调用，应改为 toast()")
	}
	if strings.Contains(s, "prompt(") {
		t.Error("前端仍存在原生 prompt() 调用，401 密钥录入应走 key-dlg 引导弹窗")
	}
}

// TestV466KeyDialog 401 密钥引导弹窗必须存在且带小白化引导文案
func TestV466KeyDialog(t *testing.T) {
	s := v466Frontend(t)
	if !strings.Contains(s, `id="key-dlg"`) {
		t.Error("缺少密钥引导弹窗 key-dlg")
	}
	// 小白化三要素：密钥是什么 / 在哪找 / 怎么填
	for _, want := range []string{"门禁卡", "gateway-key.txt", "粘贴"} {
		if !strings.Contains(s, want) {
			t.Errorf("密钥引导弹窗缺少小白化要素 %q", want)
		}
	}
	// 提交后必须自动重试挂起的请求
	if !strings.Contains(s, "function askGatewayKey(") {
		t.Error("缺少 askGatewayKey()：401 时应挂起请求并弹引导窗")
	}
	if !strings.Contains(s, "keyDlgSubmit") {
		t.Error("缺少 keyDlgSubmit()：密钥确认后应重试请求")
	}
}

// TestV466HumanErrorMessages 常见错误码必须有人话映射
func TestV466HumanErrorMessages(t *testing.T) {
	s := v466Frontend(t)
	if !strings.Contains(s, "function humanErrMsg(") {
		t.Fatal("缺少 humanErrMsg() 人话错误映射")
	}
	// 每个常见错误码都要给出可执行的下一步
	for _, want := range []string{
		"没有权限做这个操作", // 403
		"操作太快啦",       // 429
		"网关内部出了点问题", // 5xx
	} {
		if !strings.Contains(s, want) {
			t.Errorf("humanErrMsg 缺少人话文案: %q", want)
		}
	}
	// 不允许再裸抛 HTTP 401 / HTTP xxx 给用户
	if strings.Contains(s, "throw new Error('HTTP '") {
		t.Error("api() 仍在向用户抛裸 HTTP 状态码错误，应经 humanErrMsg 翻译")
	}
}

// tripwire_bridge.go — TSG v4.10.0 integration layer for prompt injection detection.
// Kingdom taxonomy: Phylum=security, Class=prompt-injection.
// Provides inbound prompt-injection scanning and outbound exfiltration detection.
//
// Tripwire is a Go-native translation of promptward (MIT, johncarmack1984),
// combined with TSG self-developed rules for detection rates exceeding promptward.

package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/HP-jh/TarsSecureGuard/tripwire"
)

// tripwireEnabled gates the detector (config.json security.tripwire.enabled)
var tripwireEnabled = true

// scanInbound checks user prompts before they reach the model.
// Returns (blocked bool, findings []tripwire.Finding).
func scanInbound(text string) (bool, []tripwire.Finding) {
	if !tripwireEnabled {
		return false, nil
	}
	res := tripwire.Scan(text, tripwire.ScanConfig{
		Direction:    tripwire.DirectionInbound,
		Source:       tripwire.SourceUser,
		MinSeverity:  tripwire.SeverityLow,
		DecodeRescan: true,
	})
	blocked := false
	for _, f := range res.Findings {
		if f.Severity >= tripwire.SeverityHigh {
			blocked = true
			break
		}
	}
	return blocked, res.Findings
}

// scanOutbound checks model outputs and tool returns for data exfiltration.
func scanOutbound(text string, src tripwire.Source) (bool, []tripwire.Finding) {
	if !tripwireEnabled {
		return false, nil
	}
	res := tripwire.Scan(text, tripwire.ScanConfig{
		Direction:    tripwire.DirectionOutbound,
		Source:       src,
		MinSeverity:  tripwire.SeverityLow,
		DecodeRescan: true,
	})
	blocked := false
	for _, f := range res.Findings {
		if f.Severity >= tripwire.SeverityHigh {
			blocked = true
			break
		}
	}
	return blocked, res.Findings
}

// ---------------------- HTTP API ----------------------

func handleTripwireScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Text      string `json:"text"`
		Direction string `json:"direction"` // "inbound" | "outbound"
		Source    string `json:"source"`    // "user" | "model" | "tool"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	dir := tripwire.DirectionInbound
	if req.Direction == "outbound" {
		dir = tripwire.DirectionOutbound
	}
	src := tripwire.SourceUser
	switch strings.ToLower(req.Source) {
	case "model":
		src = tripwire.SourceModelOutput
	case "tool":
		src = tripwire.SourceTool
	case "system":
		src = tripwire.SourceSystem
	}

	res := tripwire.Scan(req.Text, tripwire.ScanConfig{
		Direction:    dir,
		Source:       src,
		MinSeverity:  tripwire.SeverityInfo,
		DecodeRescan: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"clean":    res.Clean,
		"findings": res.Findings,
		"blocked":  !res.Clean,
	})
}

func handleTripwireStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": tripwireEnabled,
		"version": "tripwire-go-v1.0.0",
		"modules": []string{"normalize", "injection", "exfil", "decode", "markdown"},
	})
}

// doctorTripwireChecks 为 doctor 面板生成 tripwire 检查项
func doctorTripwireChecks() []doctorCheck {
	var checks []doctorCheck
	cat := "Prompt Injection 检测 (Tripwire)"
	if !tripwireEnabled {
		checks = append(checks, doctorCheck{cat, "Tripwire 状态", doctorInfo,
			"Tripwire 已禁用", "可在配置中启用 security.tripwire.enabled"})
		return checks
	}
	checks = append(checks, doctorCheck{cat, "Tripwire 状态", doctorPass,
		"Tripwire 已启用", ""})
	checks = append(checks, doctorCheck{cat, "检测引擎", doctorPass,
		"Go-native 自研 + promptward 思路吸纳", ""})
	checks = append(checks, doctorCheck{cat, "解码重扫", doctorPass,
		"Base64/Hex/URL/ROT13/Variation-Selector 二次解码检测已启用", ""})
	checks = append(checks, doctorCheck{cat, "外泄检测", doctorPass,
		"Secret/PII/信用卡/邮件/URL 外泄检测已启用", ""})
	return checks
}

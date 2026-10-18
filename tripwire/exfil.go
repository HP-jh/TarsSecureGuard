package tripwire

import (
	"regexp"
	"strings"
)

// 秘密/PII 检测签名
var exfilSigs = []struct {
	re    *regexp.Regexp
	label string
	score float64
	sev   Severity
}{
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws_access_key", 0.95, SeverityCritical},
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`), "github_token", 0.95, SeverityCritical},
	{regexp.MustCompile(`sk-(?:ant-api\d\d|proj)-[A-Za-z0-9_\-]{20,}`), "llm_api_key", 0.95, SeverityCritical},
	{regexp.MustCompile(`sk-(?:ant-)?[A-Za-z0-9]{20,}`), "llm_api_key", 0.95, SeverityCritical},
	{regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), "google_api_key", 0.90, SeverityHigh},
	{regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), "slack_token", 0.90, SeverityHigh},
	{regexp.MustCompile(`(?i)(postgres|postgresql|mysql|mongodb|redis|amqp|ftp)://[^\s:@/]+:[^\s:@/]+@`), "credential_in_url", 0.85, SeverityCritical},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}(\.[A-Za-z0-9_\-]{0,})?`), "jwt", 0.80, SeverityHigh},
	{regexp.MustCompile(`-----BEGIN [A-Z ]{0,24}PRIVATE KEY-----`), "private_key_pem", 0.95, SeverityCritical},
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "us_ssn", 0.80, SeverityHigh},
}

var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
var awsSecretRe = regexp.MustCompile(`[A-Za-z0-9/+]{40}`)
var cardRe = regexp.MustCompile(`[0-9](?:[ -]?[0-9]){12,18}`)
var phoneRe = regexp.MustCompile(`\(\d{3}\)\s*\d{3}-\d{4}|\b\d{3}-\d{3}-\d{4}\b|\b555-\d{4}\b`)
var dateRe = regexp.MustCompile(`\b(?:19|20)\d{2}-\d{2}-\d{2}\b|\b\d{2}/\d{2}/\d{4}\b`)
var addressRe = regexp.MustCompile(`\b\d{1,5}\s+[A-Z][a-z]+\s+(?:Ave|Avenue|St|Street|Rd|Road|Blvd|Lane|Ln|Dr|Drive|Way)\b`)

func luhnCheck(digits []int) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		x := digits[i]
		if alt {
			x *= 2
			if x > 9 {
				x -= 9
			}
		}
		sum += x
		alt = !alt
	}
	return sum%10 == 0
}

// ScanExfil 扫描外泄（在已规范化文本上运行）
func ScanExfil(text string, direction Direction, src Source) []Finding {
	var out []Finding

	// 特定秘密/PII形状
	for _, sig := range exfilSigs {
		for _, m := range sig.re.FindAllStringIndex(text, -1) {
			out = append(out, Finding{
				Kind:     KindExfiltration,
				Label:    sig.label,
				Severity: sig.sev,
				Score:    sig.score,
				Start:    m[0],
				End:      m[1],
				Source:   src,
			})
		}
	}

	// AWS secret access key: 裸40字符令牌本身太泛（会误抓git SHA），需AWS上下文+混合大小写
	hasAWSCtx := strings.Contains(text, "AKIA") || strings.Contains(strings.ToLower(text), "secret")
	if hasAWSCtx {
		for _, m := range awsSecretRe.FindAllStringIndex(text, -1) {
			s := text[m[0]:m[1]]
			mixed := false
			lower := false
			upper := false
			for _, c := range s {
				if c >= 'a' && c <= 'z' {
					lower = true
				}
				if c >= 'A' && c <= 'Z' {
					upper = true
				}
				if lower && upper {
					mixed = true
					break
				}
			}
			if mixed {
				out = append(out, Finding{
					Kind:     KindExfiltration,
					Label:    "aws_secret_key",
					Severity: SeverityCritical,
					Score:    0.90,
					Start:    m[0],
					End:      m[1],
					Source:   src,
				})
			}
		}
	}

	// 信用卡: 正确长度的数字串且通过Luhn校验，且不是更长数字串的一部分
	for _, m := range cardRe.FindAllStringIndex(text, -1) {
		bs, be := m[0], m[1]
		prevDigit := false
		nextDigit := false
		if bs > 0 {
			c := text[bs-1]
			prevDigit = c >= '0' && c <= '9'
		}
		if be < len(text) {
			c := text[be]
			nextDigit = c >= '0' && c <= '9'
		}
		if prevDigit || nextDigit {
			continue
		}
		var digits []int
		for i := bs; i < be; i++ {
			c := text[i]
			if c >= '0' && c <= '9' {
				digits = append(digits, int(c-'0'))
			}
		}
		if len(digits) >= 13 && len(digits) <= 19 && luhnCheck(digits) {
			out = append(out, Finding{
				Kind:     KindExfiltration,
				Label:    "credit_card",
				Severity: SeverityHigh,
				Score:    0.85,
				Start:    bs,
				End:      be,
				Source:   src,
			})
		}
	}

	// Email: 弱PII信号
	for _, m := range emailRe.FindAllStringIndex(text, -1) {
		out = append(out, Finding{
			Kind:     KindExfiltration,
			Label:    "email",
			Severity: SeverityLow,
			Score:    0.35,
			Start:    m[0],
			End:      m[1],
			Source:   src,
		})
	}

	// PII聚类: 两个或以上不同PII信号
	var piiSpans [][2]int
	for _, re := range []*regexp.Regexp{emailRe, phoneRe, dateRe, addressRe, exfilSigs[len(exfilSigs)-1].re} {
		if m := re.FindStringIndex(text); m != nil {
			piiSpans = append(piiSpans, [2]int{m[0], m[1]})
		}
	}
	if len(piiSpans) >= 2 {
		minStart := piiSpans[0][0]
		for _, sp := range piiSpans {
			if sp[0] < minStart {
				minStart = sp[0]
			}
		}
		out = append(out, Finding{
			Kind:     KindExfiltration,
			Label:    "pii_cluster",
			Severity: SeverityMedium,
			Score:    0.60,
			Start:    minStart,
			End:      minStart + 1,
			Source:   src,
		})
	}

	// Markdown/URL外泄（仅输出路径）
	if direction == DirectionOutbound {
		out = append(out, ScanMarkdown(text, src)...)
	}

	return out
}
